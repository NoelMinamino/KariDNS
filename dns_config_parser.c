#include "dns_config_parser.h"
#include "dns_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <limits.h>
#include "dns_wire.h"

static void *safe_realloc_or_die(void *ptr, size_t size) {
  void *p = realloc(ptr, size);
  if (!p && size > 0) {
    syslog(LOG_CRIT, "[Config] Out of memory during config parse (requested %zu bytes)", size);
    exit(1);
  }
  return p;
}

static void *safe_calloc_or_die(size_t nmemb, size_t size) {
  void *p = calloc(nmemb, size);
  if (!p && nmemb > 0 && size > 0) {
    syslog(LOG_CRIT, "[Config] Out of memory during config parse (requested %zu bytes)", nmemb * size);
    exit(1);
  }
  return p;
}

#define APPEND_STR(arr, cnt, val) \
    do { \
        (arr) = safe_realloc_or_die((arr), sizeof(char *) * ((cnt) + 1)); \
        (arr)[(cnt)++] = (val); \
    } while (0)

static void skip_spaces_and_comments_in_frame(config_file_frame_t *frame) {
  while (frame->pos < frame->len) {
    char c = frame->src[frame->pos];
    if (c == '\0') break;
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
      frame->pos++;
    } else if (c == '#') {
      while (frame->pos < frame->len && frame->src[frame->pos] != '\n' && frame->src[frame->pos] != '\0')
        frame->pos++;
    } else if (c == '/' && frame->pos + 1 < frame->len && frame->src[frame->pos + 1] == '/') {
      frame->pos += 2;
      while (frame->pos < frame->len && frame->src[frame->pos] != '\n' && frame->src[frame->pos] != '\0')
        frame->pos++;
    } else if (c == '/' && frame->pos + 1 < frame->len && frame->src[frame->pos + 1] == '*') {
      frame->pos += 2;
      while (frame->pos + 1 < frame->len && !(frame->src[frame->pos] == '*' && frame->src[frame->pos + 1] == '/')) {
        if (frame->src[frame->pos] == '\0') break;
        frame->pos++;
      }
      if (frame->pos + 1 < frame->len && frame->src[frame->pos] == '*' && frame->src[frame->pos + 1] == '/')
        frame->pos += 2;
    } else {
      break;
    }
  }
}

static conf_token_t get_raw_token_from_frame(config_file_frame_t *frame) {
  conf_token_t tok = {TOKEN_EOF, NULL, false};
  if (!frame || !frame->src)
    return tok;
  skip_spaces_and_comments_in_frame(frame);
  if (frame->pos >= frame->len || frame->src[frame->pos] == '\0')
    return tok;

  char c = frame->src[frame->pos];
  if (c == '{') {
    tok.type = TOKEN_LBRACE;
    frame->pos++;
    return tok;
  }
  if (c == '}') {
    tok.type = TOKEN_RBRACE;
    frame->pos++;
    return tok;
  }
  if (c == ';') {
    tok.type = TOKEN_SEMICOLON;
    frame->pos++;
    return tok;
  }
  if (c == '"') {
    frame->pos++;
    size_t start = frame->pos;
    while (frame->pos < frame->len && frame->src[frame->pos] != '"' && frame->src[frame->pos] != '\0')
      frame->pos++;
    size_t str_len = frame->pos - start;
    if (str_len > 4096) {
      syslog(LOG_WARNING, "[Config] Token length (%zu bytes) exceeds maximum limit (4096 bytes), truncating in '%s'",
             str_len, frame->file_path ? frame->file_path : "<string>");
      str_len = 4096;
    }
    tok.type = TOKEN_STRING;
    tok.is_quoted = true;
    tok.value = malloc(str_len + 1);
    if (!tok.value) return tok;
    memcpy(tok.value, &frame->src[start], str_len);
    tok.value[str_len] = '\0';
    if (frame->pos < frame->len && frame->src[frame->pos] == '"')
      frame->pos++;
    return tok;
  }

  size_t start = frame->pos;
  while (frame->pos < frame->len) {
    char nc = frame->src[frame->pos];
    if (nc == '\0' || nc == ' ' || nc == '\t' || nc == '\n' || nc == '\r' || nc == '{' ||
        nc == '}' || nc == ';' || nc == '#')
      break;
    if (nc == '/' && frame->pos + 1 < frame->len &&
        (frame->src[frame->pos + 1] == '/' || frame->src[frame->pos + 1] == '*'))
      break;
    frame->pos++;
  }
  size_t str_len = frame->pos - start;
  if (str_len == 0) {
    frame->pos++;
    str_len = 1;
  }
  if (str_len > 4096) {
    syslog(LOG_WARNING, "[Config] Token length (%zu bytes) exceeds maximum limit (4096 bytes), truncating in '%s'",
           str_len, frame->file_path ? frame->file_path : "<string>");
    str_len = 4096;
  }
  tok.type = TOKEN_STRING;
  tok.is_quoted = false;
  tok.value = malloc(str_len + 1);
  if (!tok.value) return tok;
  memcpy(tok.value, &frame->src[start], str_len);
  tok.value[str_len] = '\0';
  return tok;
}

void config_lexer_cleanup(token_ctx_t *ctx) {
  if (!ctx) return;
  for (int i = 0; i < MAX_INCLUDE_DEPTH; i++) {
    if (ctx->stack[i].owns_src && ctx->stack[i].src) {
      free(ctx->stack[i].src);
      ctx->stack[i].src = NULL;
    }
    if (ctx->stack[i].file_path) {
      free(ctx->stack[i].file_path);
      ctx->stack[i].file_path = NULL;
    }
    ctx->stack[i].owns_src = false;
    ctx->stack[i].src = NULL;
    ctx->stack[i].pos = 0;
    ctx->stack[i].len = 0;
    ctx->stack[i].dev = 0;
    ctx->stack[i].ino = 0;
  }
  ctx->depth = 0;
}

void free_token(conf_token_t *tok) {
  if (tok->value) {
    free(tok->value);
    tok->value = NULL;
  }
}

conf_token_t get_next_token(token_ctx_t *ctx) {
  while (1) {
    if (ctx->error_occurred || ctx->depth < 0 || ctx->depth >= MAX_INCLUDE_DEPTH) {
      return (conf_token_t){TOKEN_EOF, NULL, false};
    }

    config_file_frame_t *frame = &ctx->stack[ctx->depth];
    conf_token_t tok = get_raw_token_from_frame(frame);

    if (tok.type == TOKEN_EOF) {
      if (ctx->depth > 0) {
        if (frame->owns_src && frame->src) {
          free(frame->src);
          frame->src = NULL;
        }
        if (frame->file_path) {
          free(frame->file_path);
          frame->file_path = NULL;
        }
        frame->owns_src = false;
        frame->pos = 0;
        frame->len = 0;
        frame->dev = 0;
        frame->ino = 0;
        ctx->depth--;
        continue;
      }
      return tok;
    }

    if (tok.type == TOKEN_STRING && !tok.is_quoted && strcmp(tok.value, "include") == 0) {
      free_token(&tok);

      conf_token_t tok_file = get_raw_token_from_frame(frame);
      if (tok_file.type != TOKEN_STRING) {
        syslog(LOG_ERR, "[Config] syntax error: expected filename after 'include'");
        free_token(&tok_file);
        ctx->error_occurred = true;
        return (conf_token_t){TOKEN_EOF, NULL, false};
      }

      conf_token_t tok_semi = get_raw_token_from_frame(frame);
      if (tok_semi.type != TOKEN_SEMICOLON) {
        syslog(LOG_ERR, "[Config] syntax error: missing ';' after include filename '%s'", tok_file.value);
        free_token(&tok_file);
        free_token(&tok_semi);
        ctx->error_occurred = true;
        return (conf_token_t){TOKEN_EOF, NULL, false};
      }
      free_token(&tok_semi);

      const char *parent_path = frame->file_path;
      char *base_dir = parent_path ? get_base_dir(parent_path) : strdup(".");
      char resolved[PATH_MAX];
      if (tok_file.value[0] == '/') {
        snprintf(resolved, sizeof(resolved), "%s", tok_file.value);
      } else {
        snprintf(resolved, sizeof(resolved), "%s/%s", base_dir ? base_dir : ".", tok_file.value);
      }
      if (base_dir) free(base_dir);
      free_token(&tok_file);

      if (ctx->depth + 1 >= MAX_INCLUDE_DEPTH) {
        syslog(LOG_ERR, "[Config] include depth exceeded (max %d): '%s'", MAX_INCLUDE_DEPTH, resolved);
        ctx->error_occurred = true;
        return (conf_token_t){TOKEN_EOF, NULL, false};
      }

      dev_t inc_dev = 0;
      ino_t inc_ino = 0;
      char *content = read_entire_file(resolved, &inc_dev, &inc_ino);
      if (!content) {
        syslog(LOG_ERR, "[Config] failed to read include file '%s'", resolved);
        ctx->error_occurred = true;
        return (conf_token_t){TOKEN_EOF, NULL, false};
      }

      bool circular = false;
      for (int i = 0; i <= ctx->depth; i++) {
        if (ctx->stack[i].dev != 0 && ctx->stack[i].ino != 0 &&
            ctx->stack[i].dev == inc_dev && ctx->stack[i].ino == inc_ino) {
          circular = true;
          break;
        }
        if (ctx->stack[i].file_path && strcmp(ctx->stack[i].file_path, resolved) == 0) {
          circular = true;
          break;
        }
      }
      if (circular) {
        syslog(LOG_ERR, "[Config] circular include detected: '%s'", resolved);
        free(content);
        ctx->error_occurred = true;
        return (conf_token_t){TOKEN_EOF, NULL, false};
      }

      ctx->depth++;
      ctx->stack[ctx->depth].file_path = strdup(resolved);
      ctx->stack[ctx->depth].src = content;
      ctx->stack[ctx->depth].owns_src = true;
      ctx->stack[ctx->depth].pos = 0;
      ctx->stack[ctx->depth].len = strlen(content);
      ctx->stack[ctx->depth].dev = inc_dev;
      ctx->stack[ctx->depth].ino = inc_ino;

      continue;
    }

    return tok;
  }
}

void free_rate_limit_config(rate_limit_config_t *rrl) {
  if (rrl->exempt_clients) {
    for (int i = 0; i < rrl->exempt_clients_count; i++) {
      free(rrl->exempt_clients[i].ip);
    }
    free(rrl->exempt_clients);
    rrl->exempt_clients = NULL;
  }
}

void free_zone_config(zone_config_t *zone) {
  if (!zone)
    return;
  free(zone->domain);
  free(zone->type);
  free(zone->file);
  for (int i = 0; i < zone->masters_count; i++)
    free(zone->masters[i].ip);
  free(zone->masters);
  free(zone->tsig_key);
  for (int i = 0; i < zone->tsig_keys_count; i++)
    free(zone->tsig_keys[i]);
  free(zone->tsig_keys);
  for (int i = 0; i < zone->also_notify_count; i++)
    free(zone->also_notify[i].ip);
  free(zone->also_notify);
  free(zone->notify_source);
  for (int i = 0; i < zone->allow_transfer_count; i++)
    free(zone->allow_transfer[i]);
  free(zone->allow_transfer);
  for (int i = 0; i < zone->allow_update_count; i++)
    free(zone->allow_update[i]);
  free(zone->allow_update);
  free(zone->program_path);
  for (int i = 0; i < zone->program_args_count; i++)
    free(zone->program_args[i]);
  free(zone->program_args);
  free(zone->program_user);
  free_rate_limit_config(&zone->rrl);
  free(zone);
}

static void free_partial_view(view_config_t *view) {
  if (!view) return;
  if (view->name) free(view->name);
  for (int i = 0; i < view->match_clients_count; i++) free(view->match_clients[i]);
  if (view->match_clients) free(view->match_clients);
  zone_config_t *z = view->zones;
  while (z) {
    zone_config_t *next = z->next;
    free_zone_config(z);
    z = next;
  }
  free(view);
}

void free_server_config_fields(server_config_t *cfg) {
  if (!cfg) return;
  for (int j = 0; j < cfg->bind_address_count; j++)
    free(cfg->bind_addresses[j]);
  free(cfg->bind_addresses);
  cfg->bind_addresses = NULL;
  cfg->bind_address_count = 0;

  if (cfg->user) { free(cfg->user); cfg->user = NULL; }
  if (cfg->group) { free(cfg->group); cfg->group = NULL; }
  if (cfg->nsid_string) { free(cfg->nsid_string); cfg->nsid_string = NULL; }

  if (cfg->views != NULL) {
    zone_config_t *curr_flat = cfg->zones;
    while (curr_flat) {
      zone_config_t *next = curr_flat->next;
      free(curr_flat);
      curr_flat = next;
    }
    cfg->zones = NULL;

    view_config_t *v = cfg->views;
    while (v) {
      view_config_t *next_v = v->next;
      if (v->name) free(v->name);
      for (int i = 0; i < v->match_clients_count; i++) free(v->match_clients[i]);
      if (v->match_clients) free(v->match_clients);
      zone_config_t *curr = v->zones;
      while (curr) {
        zone_config_t *next = curr->next;
        free_zone_config(curr);
        curr = next;
      }
      free(v);
      v = next_v;
    }
    cfg->views = NULL;
  } else {
    zone_config_t *curr = cfg->zones;
    while (curr) {
      zone_config_t *next = curr->next;
      free_zone_config(curr);
      curr = next;
    }
    cfg->zones = NULL;
  }

  tsig_key_t *k = cfg->keys;
  while (k) {
    tsig_key_t *next_k = k->next;
    free(k->name);
    if (k->algorithm) free(k->algorithm);
    if (k->secret) free(k->secret);
    free(k);
    k = next_k;
  }
  cfg->keys = NULL;

  if (cfg->control.algorithm) { free(cfg->control.algorithm); cfg->control.algorithm = NULL; }
  if (cfg->control.secret) { free(cfg->control.secret); cfg->control.secret = NULL; }
  memset(&cfg->control, 0, sizeof(control_channel_config_t));
  free_rate_limit_config(&cfg->rrl);
  memset(&cfg->rrl, 0, sizeof(rate_limit_config_t));

  log_channel_t *ch = cfg->logging.channels;
  while (ch) {
    log_channel_t *next_ch = ch->next;
    if (ch->fd >= 0) close(ch->fd);
    if (ch->name) free(ch->name);
    if (ch->file_path) free(ch->file_path);
    free(ch);
    ch = next_ch;
  }
  cfg->logging.channels = NULL;
  cfg->logging.queries_channel = NULL;
  cfg->logging.responses_channel = NULL;
  if (cfg->logging.queries_channel_name) {
    free(cfg->logging.queries_channel_name);
    cfg->logging.queries_channel_name = NULL;
  }
  if (cfg->logging.responses_channel_name) {
    free(cfg->logging.responses_channel_name);
    cfg->logging.responses_channel_name = NULL;
  }
}

char *read_entire_file(const char *path, dev_t *out_dev, ino_t *out_ino) {
  int fd = open_via_dir_cache(path, O_RDONLY, 0, false);
  if (fd < 0)
    return NULL;
  
  if (out_dev || out_ino) {
    struct stat st;
    if (fstat(fd, &st) == 0) {
      if (out_dev) *out_dev = st.st_dev;
      if (out_ino) *out_ino = st.st_ino;
    }
  }

  FILE *f = fdopen(fd, "rb");
  if (!f) {
    close(fd);
    return NULL;
  }
  fseek(f, 0, SEEK_END);
  long fsize = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (fsize < 0 || fsize > KARIDNS_MAX_CONFIG_FILE_SIZE) {
    fclose(f);
    return NULL;
  }
  char *str = malloc(fsize + 1);
  if (!str) {
    fclose(f);
    return NULL;
  }
  if (fread(str, 1, fsize, f) != (size_t)fsize) {
    free(str);
    fclose(f);
    return NULL;
  }
  str[fsize] = '\0';
  fclose(f);
  return str;
}

static void skip_unknown_block(token_ctx_t *ctx) {
  int brace_level = 0;
  while (1) {
    conf_token_t tok = get_next_token(ctx);
    if (tok.type == TOKEN_EOF) {
      free_token(&tok);
      break;
    }
    if (tok.type == TOKEN_LBRACE)
      brace_level++;
    else if (tok.type == TOKEN_RBRACE)
      brace_level--;
    else if (tok.type == TOKEN_SEMICOLON && brace_level <= 0) {
      free_token(&tok);
      break;
    }
    free_token(&tok);
  }
}

bool match_cidr(const char *client_ip_str, const char *cidr_str) {
  if (strcmp(cidr_str, "any") == 0 || strcmp(cidr_str, "any;") == 0)
    return true;
  char cidr_copy[256];
  strncpy(cidr_copy, cidr_str, sizeof(cidr_copy) - 1);
  cidr_copy[sizeof(cidr_copy) - 1] = '\0';
  char *slash = strchr(cidr_copy, '/');
  int prefix = -1;
  if (slash) {
    *slash = '\0';
    char *endptr = NULL;
    long val = strtol(slash + 1, &endptr, 10);
    if (endptr == slash + 1 || *endptr != '\0' || val < 0 || val > 128) {
        syslog(LOG_WARNING, "[Config] Invalid CIDR prefix in ACL entry: '%s' (rejecting, no match)", cidr_str);
        return false;
    }
    prefix = (int)val;
  }
  struct in_addr client_addr_v4, net_addr_v4;
  struct in6_addr client_addr_v6, net_addr_v6;
  if (inet_pton(AF_INET, client_ip_str, &client_addr_v4) == 1 &&
      inet_pton(AF_INET, cidr_copy, &net_addr_v4) == 1) {
    if (prefix == -1)
      prefix = 32;
    if (prefix < 0 || prefix > 32)
      return false;
    uint32_t mask = prefix == 0 ? 0 : (~0U) << (32 - prefix);
    mask = htonl(mask);
    return (client_addr_v4.s_addr & mask) == (net_addr_v4.s_addr & mask);
  } else if (inet_pton(AF_INET6, client_ip_str, &client_addr_v6) == 1 &&
             inet_pton(AF_INET6, cidr_copy, &net_addr_v6) == 1) {
    if (prefix == -1)
      prefix = 128;
    if (prefix < 0 || prefix > 128)
      return false;
    for (int i = 0; i < 16; i++) {
      int bits = prefix - (i * 8);
      if (bits >= 8) {
        if (client_addr_v6.s6_addr[i] != net_addr_v6.s6_addr[i])
          return false;
      } else if (bits > 0) {
        uint8_t mask = (0xFF << (8 - bits)) & 0xFF;
        if ((client_addr_v6.s6_addr[i] & mask) !=
            (net_addr_v6.s6_addr[i] & mask))
          return false;
      } else
        break;
    }
    return true;
  }
  return false;
}

static int parse_string_list_inner(token_ctx_t *ctx, char ***list, int *count) {
  while (1) {
    conf_token_t tok = get_next_token(ctx);
    if (tok.type == TOKEN_RBRACE) {
      free_token(&tok);
      break;
    }
    if (tok.type != TOKEN_STRING) {
      free_token(&tok);
      return -1;
    }
    *list = safe_realloc_or_die(*list, sizeof(char *) * (*count + 1));
    (*list)[*count] = strdup(tok.value);
    (*count)++;
    free_token(&tok);
    tok = get_next_token(ctx);
    if (tok.type != TOKEN_SEMICOLON) {
      free_token(&tok);
      return -1;
    }
    free_token(&tok);
  }
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) {
    free_token(&tok);
    return -1;
  }
  free_token(&tok);
  return 0;
}

static int parse_string_list(token_ctx_t *ctx, char ***list, int *count) {
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_LBRACE) {
    free_token(&tok);
    return -1;
  }
  free_token(&tok);
  return parse_string_list_inner(ctx, list, count);
}

typedef enum { ACL_KEY_AS_LIST_ENTRY, ACL_KEY_AS_TSIG_FIELD } acl_key_mode_t;

static int parse_acl_list(token_ctx_t *ctx, char ***list, int *count,
                           acl_key_mode_t key_mode, char ***tsig_keys_out, int *tsig_keys_count_out) {
    conf_token_t tok = get_next_token(ctx);
    if (tok.type != TOKEN_LBRACE) { free_token(&tok); return -1; }
    free_token(&tok);

    int brace_depth = 1;
    bool in_negated_block = false;

    while (brace_depth > 0) {
        tok = get_next_token(ctx);
        if (tok.type == TOKEN_EOF) { free_token(&tok); return -1; }

        if (tok.type == TOKEN_RBRACE) {
            brace_depth--;
            free_token(&tok);
            if (brace_depth == 1 && in_negated_block) {
                in_negated_block = false;
                tok = get_next_token(ctx);
                if (tok.type != TOKEN_SEMICOLON) { free_token(&tok); return -1; }
                free_token(&tok);
            }
            continue;
        }
        if (tok.type == TOKEN_LBRACE) { brace_depth++; free_token(&tok); continue; }
        if (tok.type == TOKEN_SEMICOLON) { free_token(&tok); continue; }
        if (tok.type != TOKEN_STRING) { free_token(&tok); return -1; }

        if (strcmp(tok.value, "key") == 0) {
            free_token(&tok);
            tok = get_next_token(ctx);
            if (tok.type != TOKEN_STRING) { free_token(&tok); return -1; }
            if (key_mode == ACL_KEY_AS_TSIG_FIELD && tsig_keys_out && tsig_keys_count_out) {
                APPEND_STR(*tsig_keys_out, *tsig_keys_count_out, strdup(tok.value));
            } else {
                APPEND_STR(*list, *count, strdup(tok.value));
            }
            free_token(&tok);
        } else if (strcmp(tok.value, "!") == 0) {
            free_token(&tok);
            tok = get_next_token(ctx);
            if (tok.type == TOKEN_LBRACE) {
                brace_depth++; in_negated_block = true; free_token(&tok); continue;
            }
            if (tok.type != TOKEN_STRING) { free_token(&tok); return -1; }
            if (in_negated_block) {
                if (strcmp(tok.value, "any") != 0) {
                    APPEND_STR(*list, *count, strdup(tok.value));
                }
            } else {
                char buf[256];
                snprintf(buf, sizeof(buf), "!%s", tok.value);
                APPEND_STR(*list, *count, strdup(buf));
            }
            free_token(&tok);
        } else {
            char *val = strdup(tok.value);
            free_token(&tok);
            bool double_negated = false;
            if (in_negated_block && val[0] == '!') {
                char *unbanged = strdup(val + 1);
                free(val); val = unbanged;
                double_negated = true; // !{ !X; } => X
            }
            if (in_negated_block && strcmp(val, "any") == 0) {
                free(val);
            } else if (in_negated_block && !double_negated) {
                size_t buflen = strlen(val) + 2;
                char *negated = malloc(buflen);
                if (negated) {
                    snprintf(negated, buflen, "!%s", val);
                    APPEND_STR(*list, *count, negated);
                }
                free(val);
            } else {
                APPEND_STR(*list, *count, val);
            }
        }
        tok = get_next_token(ctx);
        if (tok.type != TOKEN_SEMICOLON) { free_token(&tok); return -1; }
        free_token(&tok);
    }
    tok = get_next_token(ctx);
    if (tok.type != TOKEN_SEMICOLON) { free_token(&tok); return -1; }
    free_token(&tok);
    return 0;
}



static int parse_ip_port_list(token_ctx_t *ctx, ip_port_t **list, int *count) {
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_LBRACE) {
    free_token(&tok);
    return -1;
  }
  free_token(&tok);
  while (1) {
    tok = get_next_token(ctx);
    if (tok.type == TOKEN_RBRACE) {
      free_token(&tok);
      break;
    }
    if (tok.type != TOKEN_STRING) {
      free_token(&tok);
      return -1;
    }
    *list = safe_realloc_or_die(*list, sizeof(ip_port_t) * (*count + 1));
    (*list)[*count].ip = strdup(tok.value);
    (*list)[*count].port = 53;
    free_token(&tok);
    tok = get_next_token(ctx);
    if (tok.type == TOKEN_STRING && strcmp(tok.value, "port") == 0) {
      free_token(&tok);
      tok = get_next_token(ctx);
      if (tok.type == TOKEN_STRING) {
        char *endptr;
        long pval = strtol(tok.value, &endptr, 10);
        if (*endptr != '\0' || pval <= 0 || pval > 65535) {
          free_token(&tok);
          return -1;
        }
        (*list)[*count].port = (int)pval;
      } else {
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      tok = get_next_token(ctx);
    }
    (*count)++;
    if (tok.type != TOKEN_SEMICOLON) {
      free_token(&tok);
      return -1;
    }
    free_token(&tok);
  }
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) {
    free_token(&tok);
    return -1;
  }
  free_token(&tok);
  return 0;
}

static int parse_rate_limit_config(token_ctx_t *ctx, rate_limit_config_t *rrl) {
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_LBRACE) {
    free_token(&tok);
    return -1;
  }
  free_token(&tok);
  rrl->configured = true;
  rrl->log_only = false;
  rrl->responses_per_second = 0;
  rrl->nxdomains_per_second = 0;
  rrl->errors_per_second = 0;
  rrl->window_seconds = 15;
  rrl->slip = 2;
  rrl->exempt_clients = NULL;
  rrl->exempt_clients_count = 0;

  while (1) {
    tok = get_next_token(ctx);
    if (tok.type == TOKEN_RBRACE) {
      free_token(&tok);
      break;
    }
    if (tok.type != TOKEN_STRING) {
      free_token(&tok);
      return -1;
    }
    char *key = strdup(tok.value);
    free_token(&tok);

    if (strcmp(key, "exempt-clients") == 0) {
      if (parse_ip_port_list(ctx, &rrl->exempt_clients, &rrl->exempt_clients_count) != 0) {
        free(key);
        return -1;
      }
      free(key);
      continue;
    }

    tok = get_next_token(ctx);
    if (tok.type != TOKEN_STRING) {
      free(key);
      free_token(&tok);
      return -1;
    }
    char *val = strdup(tok.value);
    free_token(&tok);

    tok = get_next_token(ctx);
    if (tok.type != TOKEN_SEMICOLON) {
      free(key); free(val); free_token(&tok);
      return -1;
    }
    free_token(&tok);

    char *endptr;
    long num_val = strtol(val, &endptr, 10);
    bool valid = (*endptr == '\0' && num_val >= 0);

    if (strcmp(key, "responses-per-second") == 0) {
      if (valid) rrl->responses_per_second = (int)num_val;
      else syslog(LOG_WARNING, "[Config] Invalid value '%s' for rate-limit option '%s', ignoring", val, key);
    } else if (strcmp(key, "nxdomains-per-second") == 0) {
      if (valid) rrl->nxdomains_per_second = (int)num_val;
      else syslog(LOG_WARNING, "[Config] Invalid value '%s' for rate-limit option '%s', ignoring", val, key);
    } else if (strcmp(key, "errors-per-second") == 0) {
      if (valid) rrl->errors_per_second = (int)num_val;
      else syslog(LOG_WARNING, "[Config] Invalid value '%s' for rate-limit option '%s', ignoring", val, key);
    } else if (strcmp(key, "window") == 0) {
      if (*endptr == '\0' && num_val > 0) rrl->window_seconds = (int)num_val;
      else syslog(LOG_WARNING, "[Config] Invalid value '%s' for rate-limit option '%s', ignoring", val, key);
    } else if (strcmp(key, "slip") == 0) {
      if (valid) rrl->slip = (int)num_val;
      else syslog(LOG_WARNING, "[Config] Invalid value '%s' for rate-limit option '%s', ignoring", val, key);
    } else if (strcmp(key, "log-only") == 0) {
      rrl->log_only = (strcmp(val, "yes") == 0 || strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
    } else {
      syslog(LOG_WARNING, "[Config] Unknown rate-limit option '%s'", key);
    }
    free(key);
    free(val);
  }
  
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) {
    free_token(&tok);
    return -1;
  }
  free_token(&tok);
  return 0;
}

static int parse_zone_block(token_ctx_t *ctx, zone_config_t **zone_out) {
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_STRING) {
    free_token(&tok);
    return -1;
  }
  zone_config_t *zone = safe_calloc_or_die(1, sizeof(zone_config_t));
  zone->domain = strdup(tok.value);
  free_token(&tok);
  size_t dl = strlen(zone->domain);
  if (dl > 0 && zone->domain[dl - 1] != '.') {
    char *norm = malloc(dl + 2);
    if (norm) {
      memcpy(norm, zone->domain, dl);
      norm[dl] = '.';
      norm[dl + 1] = '\0';
      free(zone->domain);
      zone->domain = norm;
    }
  }
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_LBRACE) {
    free_zone_config(zone);
    free_token(&tok);
    return -1;
  }
  free_token(&tok);
  while (1) {
    tok = get_next_token(ctx);
    if (tok.type == TOKEN_RBRACE) {
      free_token(&tok);
      break;
    }
    if (tok.type != TOKEN_STRING) {
      free_zone_config(zone);
      free_token(&tok);
      return -1;
    }
    char *key = strdup(tok.value);
    free_token(&tok);
    if (strcmp(key, "masters") == 0) {
      if (parse_ip_port_list(ctx, &zone->masters, &zone->masters_count) !=
          0) {
        free(key);
        free_zone_config(zone);
        return -1;
      }
    } else if (strcmp(key, "also-notify") == 0) {
      if (parse_ip_port_list(ctx, &zone->also_notify,
                             &zone->also_notify_count) != 0) {
        free(key);
        free_zone_config(zone);
        return -1;
      }
    } else if (strcmp(key, "allow-transfer") == 0) {
      if (parse_acl_list(ctx, &zone->allow_transfer, &zone->allow_transfer_count, ACL_KEY_AS_TSIG_FIELD, &zone->tsig_keys, &zone->tsig_keys_count) != 0) {
        free(key); free_zone_config(zone); return -1;
      }
    } else if (strcmp(key, "allow-update") == 0) {
      if (parse_acl_list(ctx, &zone->allow_update, &zone->allow_update_count, ACL_KEY_AS_LIST_ENTRY, NULL, NULL) != 0) {
        free(key); free_zone_config(zone); return -1;
      }
    } else if (strcmp(key, "type") == 0 || strcmp(key, "file") == 0 ||
               strcmp(key, "tsig-key") == 0 ||
               strcmp(key, "notify-source") == 0 ||
               strcmp(key, "catalog-zone") == 0) {
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_STRING) {
        free(key);
        free_zone_config(zone);
        free_token(&tok);
        return -1;
      }
      char *val = strdup(tok.value);
      free_token(&tok);
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_SEMICOLON) {
        free(key);
        free(val);
        free_zone_config(zone);
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      if (strcmp(key, "type") == 0) {
        if (strcasecmp(val, "primary") == 0) {
          free(val);
          zone->type = strdup("master");
        } else if (strcasecmp(val, "secondary") == 0) {
          free(val);
          zone->type = strdup("slave");
        } else if (strcasecmp(val, "master") == 0 || strcasecmp(val, "slave") == 0) {
          zone->type = val;
        } else if (strcasecmp(val, "program") == 0) {
          zone->type = val;
        } else {
          syslog(LOG_ERR, "[Config] Unknown zone type '%s' for zone '%s' (expected master/primary, slave/secondary, or program)", val, zone->domain);
          fprintf(stderr, "[ERROR] Unknown zone type '%s' for zone '%s'\n", val, zone->domain);
          free(key);
          free(val);
          free_zone_config(zone);
          return -1;
        }
      }
      else if (strcmp(key, "file") == 0)
        zone->file = val;
      else if (strcmp(key, "tsig-key") == 0)
        zone->tsig_key = val;
      else if (strcmp(key, "notify-source") == 0)
        zone->notify_source = val;
      else if (strcmp(key, "catalog-zone") == 0) {
        if (strcasecmp(val, "yes") == 0)
          zone->is_catalog = true;
        free(val);
      }
    } else if (strcmp(key, "program") == 0) {
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_STRING) { free(key); free_zone_config(zone); free_token(&tok); return -1; }
      if (tok.value[0] != '/') {
        fprintf(stderr, "[Config Error] 'program' path must be an absolute path (starting with '/'): %s\n",
                tok.value);
        free(key); free_zone_config(zone); free_token(&tok); return -1;
      }
      zone->program_path = strdup(tok.value);
      free_token(&tok);
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_SEMICOLON) { free(key); free_zone_config(zone); free_token(&tok); return -1; }
      free_token(&tok);
    } else if (strcmp(key, "program-args") == 0) {
      if (parse_string_list(ctx, &zone->program_args, &zone->program_args_count) != 0) {
        free(key); free_zone_config(zone); return -1;
      }
    } else if (strcmp(key, "program-user") == 0) {
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_STRING) { free(key); free_zone_config(zone); free_token(&tok); return -1; }
      zone->program_user = strdup(tok.value);
      free_token(&tok);
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_SEMICOLON) { free(key); free_zone_config(zone); free_token(&tok); return -1; }
      free_token(&tok);
    } else if (strcmp(key, "program-timeout") == 0) {
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_STRING) { free(key); free_zone_config(zone); free_token(&tok); return -1; }
      char *endptr = NULL;
      unsigned long val_num = strtoul(tok.value, &endptr, 10);
      if (*endptr == '\0') {
        zone->program_timeout_ms = (uint32_t)val_num;
      }
      free_token(&tok);
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_SEMICOLON) { free(key); free_zone_config(zone); free_token(&tok); return -1; }
      free_token(&tok);
    } else if (strcmp(key, "program-max-failures") == 0) {
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_STRING) { free(key); free_zone_config(zone); free_token(&tok); return -1; }
      char *endptr = NULL;
      unsigned long val_num = strtoul(tok.value, &endptr, 10);
      if (*endptr == '\0') {
        zone->program_max_failures = (uint32_t)val_num;
      }
      free_token(&tok);
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_SEMICOLON) { free(key); free_zone_config(zone); free_token(&tok); return -1; }
      free_token(&tok);
    } else if (strcmp(key, "rate-limit") == 0) {
      if (parse_rate_limit_config(ctx, &zone->rrl) != 0) {
        free(key);
        free_zone_config(zone);
        return -1;
      }
    } else
      skip_unknown_block(ctx);
    free(key);
  }
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) {
    free_zone_config(zone);
    free_token(&tok);
    return -1;
  }
  free_token(&tok);
  if (!zone->type) {
    zone->type = strdup("master");
  }
  if (zone->type && strcasecmp(zone->type, "program") == 0) {
    if (zone->file) {
      syslog(LOG_WARNING, "[Config] Zone '%s' is type 'program' but has 'file' configured; ignoring file", zone->domain);
    }
    if (zone->masters_count > 0) {
      syslog(LOG_WARNING, "[Config] Zone '%s' is type 'program' but has 'masters' configured; ignoring masters", zone->domain);
    }
  }
  if (zone->allow_update_count > 0 && zone->type &&
      (strcasecmp(zone->type, "slave") == 0 || strcasecmp(zone->type, "secondary") == 0)) {
    syslog(LOG_WARNING,
           "[Config] Zone '%s' is type 'slave'/'secondary' but has 'allow-update' configured; "
           "Dynamic Update requests to secondary zones will be rejected at runtime with NOTAUTH (RFC 2136)",
           zone->domain);
    fprintf(stderr,
           "[WARNING] Zone '%s' is type 'slave'/'secondary' but has 'allow-update' configured; "
           "Dynamic Update requests to secondary zones will be rejected at runtime with NOTAUTH (RFC 2136)\n",
           zone->domain);
  }
  *zone_out = zone;
  return 0;
}

static int parse_buffer_size_value(const char *str) {
  if (!str || !*str) return 0;
  char *endptr = NULL;
  long long val = strtoll(str, &endptr, 10);
  if (val <= 0) return 0;
  if (endptr && *endptr) {
    if (*endptr == 'k' || *endptr == 'K') val *= 1024;
    else if (*endptr == 'm' || *endptr == 'M') val *= 1024 * 1024;
    else if (*endptr == 'g' || *endptr == 'G') val *= 1024 * 1024 * 1024;
  }
  if (val > INT_MAX) val = INT_MAX;
  return (int)val;
}

static int parse_named_conf_internal(token_ctx_t *ctx, server_config_t *config) {
  memset(config, 0, sizeof(server_config_t));
  config->port = 53;
  config->bind_addresses = NULL;
  config->bind_address_count = 0;
  config->zones = NULL;
  config->views = NULL;
  config->keys = NULL;
  config->user = NULL;
  config->group = NULL;
  config->serve_stale = true;
  config->send_extended_errors = true;
  config->tcp_connection_reuse = false;
  config->nsid_string = NULL;
  config->tcp_idle_timeout = 10000;
  config->minimal_responses = false;
  config->minimal_any = false;
  config->minimal_any_ttl = 86400;
  config->max_mqtypes = 4;
  config->rfc10029_mqtype_enable = false;
  config->udp_recvbuf_size = 4 * 1024 * 1024;
  config->udp_sndbuf_size = 4 * 1024 * 1024;
  bool saw_view_block = false;
  bool saw_top_level_zone = false;
  view_config_t *last_view = NULL;
  zone_config_t *last_zone = NULL;
  tsig_key_t *last_key = NULL;
  while (1) {
    conf_token_t tok = get_next_token(ctx);
    if (ctx->error_occurred) {
      free_token(&tok);
      return -1;
    }
    if (tok.type == TOKEN_EOF)
      break;
    if (tok.type != TOKEN_STRING) {
      free_token(&tok);
      return -1;
    }
    if (strcmp(tok.value, "options") == 0) {
      free_token(&tok);
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_LBRACE) {
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      while (1) {
        tok = get_next_token(ctx);
        if (tok.type == TOKEN_RBRACE) {
          free_token(&tok);
          break;
        }
        if (tok.type != TOKEN_STRING) {
          free_token(&tok);
          return -1;
        }
        char *key = strdup(tok.value);
        free_token(&tok);
        if (strcmp(key, "port") == 0 || strcmp(key, "user") == 0 ||
            strcmp(key, "group") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) {
            free(key);
            free_token(&tok);
            return -1;
          }
          char *val = strdup(tok.value);
          free_token(&tok);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(key);
            free(val);
            free_token(&tok);
            return -1;
          }
          free_token(&tok);
          if (strcmp(key, "port") == 0) {
            char *endptr;
            long pval = strtol(val, &endptr, 10);
            if (*endptr == '\0' && pval > 0 && pval <= 65535) config->port = (int)pval;
            free(val);
          } else if (strcmp(key, "user") == 0)
            config->user = val;
          else
            config->group = val;
        } else if (strcmp(key, "bind-address") == 0) {
          tok = get_next_token(ctx);
          if (tok.type == TOKEN_LBRACE) {
            free_token(&tok);
            if (parse_string_list_inner(ctx, &config->bind_addresses,
                                  &config->bind_address_count) != 0) {
              free(key);
              return -1;
            }
          } else if (tok.type == TOKEN_STRING) {
            config->bind_addresses =
                safe_realloc_or_die(config->bind_addresses,
                        sizeof(char *) * (config->bind_address_count + 1));
            config->bind_addresses[config->bind_address_count++] =
                strdup(tok.value);
            free_token(&tok);
            tok = get_next_token(ctx);
            if (tok.type != TOKEN_SEMICOLON) {
              free(key);
              free_token(&tok);
              return -1;
            }
            free_token(&tok);
          } else {
            free(key);
            free_token(&tok);
            return -1;
          }
        } else if (strcmp(key, "rate-limit") == 0) {
          if (parse_rate_limit_config(ctx, &config->rrl) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "send-extended-errors") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) {
            free(key);
            free_token(&tok);
            return -1;
          }
          if (strcmp(tok.value, "yes") == 0 || strcmp(tok.value, "true") == 0)
            config->send_extended_errors = true;
          else if (strcmp(tok.value, "no") == 0 || strcmp(tok.value, "false") == 0)
            config->send_extended_errors = false;
          free_token(&tok);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(key);
            return -1;
          }
          free_token(&tok);
        } else if (strcmp(key, "serve-stale") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) {
            free(key);
            free_token(&tok);
            return -1;
          }
          if (strcmp(tok.value, "yes") == 0 || strcmp(tok.value, "true") == 0)
            config->serve_stale = true;
          else if (strcmp(tok.value, "no") == 0 || strcmp(tok.value, "false") == 0)
            config->serve_stale = false;
          free_token(&tok);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(key);
            return -1;
          }
          free_token(&tok);
        } else if (strcmp(key, "rfc10029-mqtype") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) {
            free(key);
            free_token(&tok);
            return -1;
          }
          if (strcmp(tok.value, "yes") == 0 || strcmp(tok.value, "true") == 0)
            config->rfc10029_mqtype_enable = true;
          else if (strcmp(tok.value, "no") == 0 || strcmp(tok.value, "false") == 0)
            config->rfc10029_mqtype_enable = false;
          free_token(&tok);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(key);
            return -1;
          }
          free_token(&tok);
        } else if (strcmp(key, "tcp-connection-reuse") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) { free(key); free_token(&tok); return -1; }
          if (strcmp(tok.value, "yes") == 0 || strcmp(tok.value, "true") == 0) config->tcp_connection_reuse = true;
          else if (strcmp(tok.value, "no") == 0 || strcmp(tok.value, "false") == 0) config->tcp_connection_reuse = false;
          free_token(&tok);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_SEMICOLON) { free(key); free_token(&tok); return -1; }
          free_token(&tok);
        } else if (strcmp(key, "tcp-idle-timeout") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) { free(key); free_token(&tok); return -1; }
          char *endptr;
          unsigned long v = strtoul(tok.value, &endptr, 10);
          if (*endptr != '\0' || tok.value[0] == '-' || isspace((unsigned char)tok.value[0])) {
            syslog(LOG_ERR, "[Config] Invalid tcp-idle-timeout value '%s' (must be a non-negative integer)", tok.value);
            fprintf(stderr, "[ERROR] Invalid tcp-idle-timeout value '%s' (must be a non-negative integer)\n", tok.value);
            free(key); free_token(&tok); return -1;
          }
          config->tcp_idle_timeout = (int)v;
          free_token(&tok);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_SEMICOLON) { free(key); free_token(&tok); return -1; }
          free_token(&tok);
        } else if (strcmp(key, "nsid") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) { free(key); free_token(&tok); return -1; }
          config->nsid_string = strdup(tok.value);
          free_token(&tok);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_SEMICOLON) { free(key); free_token(&tok); return -1; }
          free_token(&tok);
        } else if (strcmp(key, "minimal-responses") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) {
            free(key);
            free_token(&tok);
            return -1;
          }
          if (strcmp(tok.value, "yes") == 0 || strcmp(tok.value, "true") == 0)
            config->minimal_responses = true;
          else if (strcmp(tok.value, "no") == 0 || strcmp(tok.value, "false") == 0)
            config->minimal_responses = false;
          free_token(&tok);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(key);
            return -1;
          }
          free_token(&tok);
        } else if (strcmp(key, "minimal-any") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) {
            free(key);
            free_token(&tok);
            return -1;
          }
          if (strcmp(tok.value, "yes") == 0 || strcmp(tok.value, "true") == 0)
            config->minimal_any = true;
          else if (strcmp(tok.value, "no") == 0 || strcmp(tok.value, "false") == 0)
            config->minimal_any = false;
          free_token(&tok);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(key);
            return -1;
          }
          free_token(&tok);
        } else if (strcmp(key, "allow-program-zones") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) {
            free(key);
            free_token(&tok);
            return -1;
          }
          if (strcmp(tok.value, "yes") == 0 || strcmp(tok.value, "true") == 0)
            config->allow_program_zones = true;
          else if (strcmp(tok.value, "no") == 0 || strcmp(tok.value, "false") == 0)
            config->allow_program_zones = false;
          free_token(&tok);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(key);
            free_token(&tok);
            return -1;
          }
          free_token(&tok);
        } else if (strcmp(key, "max-mqtypes") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) {
            free(key);
            free_token(&tok);
            return -1;
          }
          char *endptr;
          long mqval = strtol(tok.value, &endptr, 10);
          if (*endptr == '\0') {
            if (mqval < 0) mqval = 0;
            if (mqval > 16) mqval = 16;
            config->max_mqtypes = (int)mqval;
          }
          free_token(&tok);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(key);
            return -1;
          }
          free_token(&tok);
        } else if (strcmp(key, "minimal-any-ttl") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) {
            free(key);
            free_token(&tok);
            return -1;
          }
          char *endptr;
          unsigned long v = strtoul(tok.value, &endptr, 10);
          if (*endptr != '\0' || tok.value[0] == '-' || isspace((unsigned char)tok.value[0])) {
            syslog(LOG_ERR, "[Config] Invalid minimal-any-ttl value '%s' (must be a non-negative integer)", tok.value);
            fprintf(stderr, "[ERROR] Invalid minimal-any-ttl value '%s' (must be a non-negative integer)\n", tok.value);
            free(key); free_token(&tok); return -1;
          }
          config->minimal_any_ttl = (uint32_t)v;
          free_token(&tok);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(key);
            return -1;
          }
          free_token(&tok);
        } else if (strcmp(key, "udp-recvbuf-size") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) {
            free(key);
            free_token(&tok);
            return -1;
          }
          int sz = parse_buffer_size_value(tok.value);
          if (sz > 0) config->udp_recvbuf_size = sz;
          free_token(&tok);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(key);
            return -1;
          }
          free_token(&tok);
        } else if (strcmp(key, "udp-sndbuf-size") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) {
            free(key);
            free_token(&tok);
            return -1;
          }
          int sz = parse_buffer_size_value(tok.value);
          if (sz > 0) config->udp_sndbuf_size = sz;
          free_token(&tok);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(key);
            return -1;
          }
          free_token(&tok);
        } else
          skip_unknown_block(ctx);
        free(key);
      }
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_SEMICOLON) {
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
    } else if (strcmp(tok.value, "view") == 0) {
      free_token(&tok);
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_STRING) { free_token(&tok); return -1; }
      view_config_t *view = safe_calloc_or_die(1, sizeof(view_config_t));
      view->name = strdup(tok.value);
      free_token(&tok);
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_LBRACE) { free(view->name); free(view); free_token(&tok); return -1; }
      free_token(&tok);
      zone_config_t *last_view_zone = NULL;
      while (1) {
        tok = get_next_token(ctx);
        if (tok.type == TOKEN_RBRACE) { free_token(&tok); break; }
        if (tok.type != TOKEN_STRING) { free_partial_view(view); free_token(&tok); return -1; }
        if (strcmp(tok.value, "match-clients") == 0) {
          free_token(&tok);
          if (parse_acl_list(ctx, &view->match_clients, &view->match_clients_count,
                             ACL_KEY_AS_LIST_ENTRY, NULL, NULL) != 0) {
            free_partial_view(view);
            return -1;
          }
        } else if (strcmp(tok.value, "zone") == 0) {
          free_token(&tok);
          zone_config_t *z = NULL;
          if (parse_zone_block(ctx, &z) != 0) {
            free_partial_view(view);
            return -1;
          }
          for (zone_config_t *existing = view->zones; existing; existing = existing->next) {
            if (strcasecmp(existing->domain, z->domain) == 0) {
              syslog(LOG_ERR, "[Config] Duplicate zone '%s' defined in view '%s'; rejecting configuration", z->domain, view->name);
              fprintf(stderr, "[ERROR] Duplicate zone '%s' defined in view '%s'\n", z->domain, view->name);
              free_zone_config(z);
              free_partial_view(view);
              return -1;
            }
          }
          if (!view->zones) view->zones = z; else last_view_zone->next = z;
          last_view_zone = z;
        } else {
          free_token(&tok);
          skip_unknown_block(ctx);
        }
      }
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_SEMICOLON) { free_partial_view(view); free_token(&tok); return -1; }
      free_token(&tok);
      for (view_config_t *existing = config->views; existing; existing = existing->next) {
        if (strcasecmp(existing->name, view->name) == 0) {
          syslog(LOG_ERR, "[Config] Duplicate view '%s' defined; rejecting configuration", view->name);
          fprintf(stderr, "[ERROR] Duplicate view '%s' defined\n", view->name);
          free_partial_view(view);
          return -1;
        }
      }
      saw_view_block = true;
      if (!config->views) config->views = view; else last_view->next = view;
      last_view = view;
    } else if (strcmp(tok.value, "zone") == 0) {
      free_token(&tok);
      zone_config_t *zone = NULL;
      if (parse_zone_block(ctx, &zone) != 0) return -1;
      for (zone_config_t *existing = config->zones; existing; existing = existing->next) {
        if (strcasecmp(existing->domain, zone->domain) == 0) {
          syslog(LOG_ERR, "[Config] Duplicate zone '%s' defined (top-level); rejecting configuration", zone->domain);
          fprintf(stderr, "[ERROR] Duplicate zone '%s' defined\n", zone->domain);
          free_zone_config(zone);
          return -1;
        }
      }
      saw_top_level_zone = true;
      if (!config->zones)
        config->zones = zone;
      else
        last_zone->next = zone;
      last_zone = zone;
    } else if (strcmp(tok.value, "key") == 0) {
      free_token(&tok);
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_STRING) {
        free_token(&tok);
        return -1;
      }
      tsig_key_t *tsig = safe_calloc_or_die(1, sizeof(tsig_key_t));
      tsig->name = strdup(tok.value);
      free_token(&tok);
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_LBRACE) {
        free(tsig->name);
        free(tsig);
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      while (1) {
        tok = get_next_token(ctx);
        if (tok.type == TOKEN_RBRACE) {
          free_token(&tok);
          break;
        }
        if (tok.type != TOKEN_STRING) {
          free(tsig->name);
          if (tsig->algorithm) free(tsig->algorithm);
          if (tsig->secret) free(tsig->secret);
          free(tsig);
          free_token(&tok);
          return -1;
        }
        char *key_prop = strdup(tok.value);
        free_token(&tok);
        if (strcmp(key_prop, "algorithm") == 0 ||
            strcmp(key_prop, "secret") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) {
            free(key_prop);
            free(tsig->name);
            if (tsig->algorithm) free(tsig->algorithm);
            if (tsig->secret) free(tsig->secret);
            free(tsig);
            free_token(&tok);
            return -1;
          }
          char *val = strdup(tok.value);
          free_token(&tok);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(key_prop);
            free(val);
            free(tsig->name);
            if (tsig->algorithm) free(tsig->algorithm);
            if (tsig->secret) free(tsig->secret);
            free(tsig);
            free_token(&tok);
            return -1;
          }
          free_token(&tok);
          if (strcmp(key_prop, "algorithm") == 0) {
            if (!tsig_algorithm_is_supported(val)) {
              syslog(LOG_ERR, "[Config] Unsupported TSIG algorithm: %s", val);
              fprintf(stderr, "[ERROR] Unsupported TSIG algorithm: %s\n", val);
              free(key_prop);
              free(val);
              free(tsig->name);
              if (tsig->algorithm) free(tsig->algorithm);
              if (tsig->secret) free(tsig->secret);
              free(tsig);
              return -1;
            }
            if (strstr(val, "md5") || strstr(val, "sha1")) {
              syslog(LOG_WARNING, "[Config] Warning: TSIG algorithm '%s' is deprecated and insecure (RFC 8945)", val);
            }
            tsig->algorithm = val;
          } else {
            tsig->secret = val;
            size_t slen = strlen(tsig->secret);
            size_t decoded_upper_bound = ((slen + 3) / 4) * 3;
            if (slen == 0 || decoded_upper_bound > sizeof(tsig->secret_decoded)) {
              syslog(LOG_ERR, "[Config] secret too long for algorithm (decodes to %zu bytes, max %zu)", decoded_upper_bound, sizeof(tsig->secret_decoded));
              fprintf(stderr, "[ERROR] secret too long for algorithm\n");
              free(key_prop);
              free(val);
              tsig->secret = NULL;
              free(tsig->name);
              if (tsig->algorithm) free(tsig->algorithm);
              free(tsig);
              return -1;
            }
            int len = EVP_DecodeBlock(tsig->secret_decoded,
                                      (const unsigned char *)tsig->secret,
                                      slen);
            if (len < 0) {
              free(key_prop);
              free(val);
              tsig->secret = NULL;
              free(tsig->name);
              if (tsig->algorithm) free(tsig->algorithm);
              free(tsig);
              return -1;
            }
            int padding = 0;
            if (slen > 0 && tsig->secret[slen - 1] == '=')
              padding++;
            if (slen > 1 && tsig->secret[slen - 2] == '=')
              padding++;
            tsig->secret_decoded_len = len - padding;
          }
        } else
          skip_unknown_block(ctx);
        free(key_prop);
      }
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_SEMICOLON) {
        free(tsig->name);
        if (tsig->algorithm) free(tsig->algorithm);
        if (tsig->secret) free(tsig->secret);
        free(tsig);
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      for (tsig_key_t *existing = config->keys; existing; existing = existing->next) {
        if (strcasecmp(existing->name, tsig->name) == 0) {
          syslog(LOG_ERR, "[Config] Duplicate TSIG key '%s' defined; rejecting configuration", tsig->name);
          fprintf(stderr, "[ERROR] Duplicate TSIG key '%s' defined\n", tsig->name);
          free(tsig->name);
          if (tsig->algorithm) free(tsig->algorithm);
          if (tsig->secret) free(tsig->secret);
          free(tsig);
          return -1;
        }
      }
      if (!config->keys)
        config->keys = tsig;
      else
        last_key->next = tsig;
      last_key = tsig;
    } else if (strcmp(tok.value, "control-channel") == 0) {
      free_token(&tok);
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_LBRACE) {
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      config->control.enabled = true;
      while (1) {
        tok = get_next_token(ctx);
        if (tok.type == TOKEN_RBRACE) {
          free_token(&tok);
          break;
        }
        if (tok.type != TOKEN_STRING) {
          free_token(&tok);
          return -1;
        }
        char *key_prop = strdup(tok.value);
        free_token(&tok);
        if (strcmp(key_prop, "algorithm") == 0 ||
            strcmp(key_prop, "secret") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) {
            free(key_prop);
            free_token(&tok);
            return -1;
          }
          char *val = strdup(tok.value);
          free_token(&tok);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(key_prop);
            free(val);
            free_token(&tok);
            return -1;
          }
          free_token(&tok);
          if (strcmp(key_prop, "algorithm") == 0) {
            if (!tsig_algorithm_is_supported(val)) {
              syslog(LOG_ERR, "[Config] Unsupported TSIG algorithm in controls: %s", val);
              fprintf(stderr, "[ERROR] Unsupported TSIG algorithm in controls: %s\n", val);
              free(key_prop);
              free(val);
              free_token(&tok);
              return -1;
            }
            if (strstr(val, "md5") || strstr(val, "sha1")) {
              syslog(LOG_WARNING, "[Config] Warning: TSIG algorithm '%s' is deprecated and insecure (RFC 8945)", val);
            }
            config->control.algorithm = val;
          } else {
            config->control.secret = val;
            size_t slen = strlen(config->control.secret);
            size_t decoded_upper_bound = ((slen + 3) / 4) * 3;
            if (slen == 0 || decoded_upper_bound > sizeof(config->control.secret_decoded)) {
              syslog(LOG_ERR, "[Config] secret too long for algorithm (decodes to %zu bytes, max %zu)", decoded_upper_bound, sizeof(config->control.secret_decoded));
              fprintf(stderr, "[ERROR] secret too long for algorithm\n");
              free(key_prop);
              free(val);
              config->control.secret = NULL;
              free_token(&tok);
              return -1;
            }
            int len = EVP_DecodeBlock(config->control.secret_decoded,
                                      (const unsigned char *)config->control.secret,
                                      slen);
            if (len < 0) {
              free(key_prop);
              free(val);
              config->control.secret = NULL;
              free_token(&tok);
              return -1;
            }
            int padding = 0;
            if (slen > 0 && config->control.secret[slen - 1] == '=')
              padding++;
            if (slen > 1 && config->control.secret[slen - 2] == '=')
              padding++;
            config->control.secret_decoded_len = len - padding;
          }
        } else
          skip_unknown_block(ctx);
        free(key_prop);
      }
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_SEMICOLON) {
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
    } else if (strcmp(tok.value, "logging") == 0) {
      free_token(&tok);
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_LBRACE) {
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      while (1) {
        tok = get_next_token(ctx);
        if (tok.type == TOKEN_RBRACE) {
          free_token(&tok);
          break;
        }
        if (tok.type != TOKEN_STRING) {
          free_token(&tok);
          return -1;
        }
        char *dir = strdup(tok.value);
        free_token(&tok);
        if (strcmp(dir, "channel") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) {
            free(dir);
            free_token(&tok);
            return -1;
          }
          log_channel_t *ch = safe_calloc_or_die(1, sizeof(log_channel_t));
          ch->name = strdup(tok.value);
          free_token(&tok);
          ch->fd = -1;
          pthread_mutex_init(&ch->lock, NULL);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_LBRACE) {
            free(dir);
            free_token(&tok);
            return -1;
          }
          free_token(&tok);
          while (1) {
            tok = get_next_token(ctx);
            if (tok.type == TOKEN_RBRACE) {
              free_token(&tok);
              break;
            }
            if (tok.type != TOKEN_STRING) {
              free_token(&tok);
              return -1;
            }
            char *opt = strdup(tok.value);
            free_token(&tok);
            if (strcmp(opt, "file") == 0) {
              tok = get_next_token(ctx);
              if (tok.type != TOKEN_STRING) {
                free(opt);
                free_token(&tok);
                return -1;
              }
              ch->file_path = strdup(tok.value);
              free_token(&tok);
              while (1) {
                tok = get_next_token(ctx);
                if (tok.type == TOKEN_EOF) {
                  free_token(&tok);
                  break;
                }
                if (tok.type == TOKEN_SEMICOLON) {
                  free_token(&tok);
                  break;
                }
                if (tok.type == TOKEN_STRING &&
                    strcmp(tok.value, "versions") == 0) {
                  free_token(&tok);
                  tok = get_next_token(ctx);
                  if (tok.type == TOKEN_STRING) {
                    char *endptr;
                    long vval = strtol(tok.value, &endptr, 10);
                    if (*endptr == '\0' && vval >= 0) ch->versions = (int)vval;
                  }
                  free_token(&tok);
                } else if (tok.type == TOKEN_STRING &&
                           strcmp(tok.value, "size") == 0) {
                  free_token(&tok);
                  tok = get_next_token(ctx);
                  if (tok.type == TOKEN_STRING) {
                    size_t mult = 1;
                    size_t len = strlen(tok.value);
                    if (len > 0) {
                      char last = tok.value[len - 1];
                      char numeric_part[64];
                      size_t numeric_len = len;
                      if (last == 'M' || last == 'm') {
                        mult = 1024 * 1024;
                        numeric_len--;
                      } else if (last == 'K' || last == 'k') {
                        mult = 1024;
                        numeric_len--;
                      } else if (last == 'G' || last == 'g') {
                        mult = 1024 * 1024 * 1024;
                        numeric_len--;
                      }
                      if (numeric_len == 0 || numeric_len >= sizeof(numeric_part) || tok.value[0] == '-' || isspace((unsigned char)tok.value[0])) {
                        syslog(LOG_ERR, "[Config] Invalid log channel size value '%s'", tok.value);
                        fprintf(stderr, "[ERROR] Invalid log channel size value '%s'\n", tok.value);
                      } else {
                        memcpy(numeric_part, tok.value, numeric_len);
                        numeric_part[numeric_len] = '\0';
                        char *endptr;
                        unsigned long long v = strtoull(numeric_part, &endptr, 10);
                        if (*endptr == '\0') {
                          ch->size_limit = v * mult;
                        } else {
                          syslog(LOG_ERR, "[Config] Invalid log channel size value '%s'", tok.value);
                          fprintf(stderr, "[ERROR] Invalid log channel size value '%s'\n", tok.value);
                        }
                      }
                    }
                  }
                  free_token(&tok);
                } else if (tok.type == TOKEN_STRING &&
                           strcmp(tok.value, "suffix") == 0) {
                  free_token(&tok);
                  tok = get_next_token(ctx);
                  if (tok.type == TOKEN_STRING &&
                      strcmp(tok.value, "timestamp") == 0)
                    ch->suffix_timestamp = true;
                  free_token(&tok);
                } else {
                  free_token(&tok);
                }
              }
            } else if (strcmp(opt, "print-time") == 0 ||
                       strcmp(opt, "print-category") == 0 ||
                       strcmp(opt, "print-severity") == 0) {
              tok = get_next_token(ctx);
              bool val =
                  (tok.type == TOKEN_STRING && strcmp(tok.value, "yes") == 0);
              free_token(&tok);
              tok = get_next_token(ctx);
              if (tok.type == TOKEN_SEMICOLON)
                free_token(&tok);
              if (strcmp(opt, "print-time") == 0)
                ch->print_time = val;
              else if (strcmp(opt, "print-category") == 0)
                ch->print_category = val;
              else
                ch->print_severity = val;
            } else
              skip_unknown_block(ctx);
            free(opt);
          }
          tok = get_next_token(ctx);
          if (tok.type == TOKEN_SEMICOLON)
            free_token(&tok);
          ch->next = config->logging.channels;
          config->logging.channels = ch;
        } else if (strcmp(dir, "category") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) {
            free(dir);
            free_token(&tok);
            return -1;
          }
          char *cat_name = strdup(tok.value);
          free_token(&tok);
          tok = get_next_token(ctx);
          if (tok.type == TOKEN_LBRACE) {
            free_token(&tok);
            tok = get_next_token(ctx);
            if (strcmp(cat_name, "queries") == 0 && tok.type == TOKEN_STRING)
              config->logging.queries_channel_name = strdup(tok.value);
            else if (strcmp(cat_name, "responses") == 0 && tok.type == TOKEN_STRING)
              config->logging.responses_channel_name = strdup(tok.value);
            else {
              syslog(LOG_WARNING, "[Config] Unknown logging category '%s', ignoring", cat_name);
              fprintf(stderr, "[WARNING] Unknown logging category '%s', ignoring\n", cat_name);
            }
            free_token(&tok);
            tok = get_next_token(ctx);
            if (tok.type == TOKEN_SEMICOLON)
              free_token(&tok);
            tok = get_next_token(ctx);
            if (tok.type == TOKEN_RBRACE)
              free_token(&tok);
          }
          free(cat_name);
          tok = get_next_token(ctx);
          if (tok.type == TOKEN_SEMICOLON)
            free_token(&tok);
        } else
          skip_unknown_block(ctx);
        free(dir);
      }
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_SEMICOLON) {
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      if (config->logging.queries_channel_name) {
        log_channel_t *ch = config->logging.channels;
        while (ch) {
          if (strcmp(ch->name, config->logging.queries_channel_name) == 0) {
            config->logging.queries_channel = ch;
            break;
          }
          ch = ch->next;
        }
        if (!config->logging.queries_channel) {
          syslog(LOG_ERR, "[Config] logging category 'queries' references undefined channel '%s'",
                 config->logging.queries_channel_name);
          fprintf(stderr, "[ERROR] logging category 'queries' references undefined channel '%s'\n",
                 config->logging.queries_channel_name);
          return -1;
        }
      }
      if (config->logging.responses_channel_name) {
        log_channel_t *ch = config->logging.channels;
        while (ch) {
          if (strcmp(ch->name, config->logging.responses_channel_name) == 0) {
            config->logging.responses_channel = ch;
            break;
          }
          ch = ch->next;
        }
        if (!config->logging.responses_channel) {
          syslog(LOG_ERR, "[Config] logging category 'responses' references undefined channel '%s'",
                 config->logging.responses_channel_name);
          fprintf(stderr, "[ERROR] logging category 'responses' references undefined channel '%s'\n",
                 config->logging.responses_channel_name);
          return -1;
        }
      }
    } else {
      free_token(&tok);
      skip_unknown_block(ctx);
    }
  }
  if (saw_view_block && saw_top_level_zone) {
    syslog(LOG_ERR, "Cannot mix top-level zone and view blocks");
    // トップレベル直付けの zone_config_t リストを完全解放してリークを防ぐ
    zone_config_t *curr = config->zones;
    while (curr) {
      zone_config_t *next = curr->next;
      free_zone_config(curr);
      curr = next;
    }
    config->zones = NULL;
    return -1;
  }
  if (!saw_view_block) {
    view_config_t *default_view = safe_calloc_or_die(1, sizeof(view_config_t));
    default_view->name = strdup("__default__");
    default_view->match_clients = safe_calloc_or_die(1, sizeof(char *));
    default_view->match_clients[0] = strdup("any");
    default_view->match_clients_count = 1;
    default_view->zones = config->zones;
    config->views = default_view;
  }

  // Create a flattened list of zones in config->zones for backward compatibility
  // (AXFR, RRL, control-channel etc).
  // ※ このリストは所有権を持たない走査・参照専用リストです。
  //   各ノードはビュー内ゾーン(v->zones)の内部ポインタを共有しているため、
  //   フィールドの書き込みや free_zone_config() の呼び出しは絶対に行わないこと。
  //   解放時は free_server_config_fields() 内でノード構造体自体のみを free() すること。
  zone_config_t *flat_zones = NULL;
  zone_config_t *flat_tail = NULL;
  for (view_config_t *v = config->views; v; v = v->next) {
    for (zone_config_t *z = v->zones; z; z = z->next) {
      zone_config_t *dup_z = safe_calloc_or_die(1, sizeof(zone_config_t));
      *dup_z = *z;
      dup_z->next = NULL;
      if (!flat_zones) {
        flat_zones = dup_z;
        flat_tail = dup_z;
      } else {
        flat_tail->next = dup_z;
        flat_tail = dup_z;
      }
    }
  }
  config->zones = flat_zones;

  return 0;
}

int parse_named_conf_ext(const char *config_str, const char *initial_file_path, server_config_t *config) {
  if (!config_str || !config) return -1;
  token_ctx_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.stack[0].file_path = initial_file_path ? strdup(initial_file_path) : NULL;
  ctx.stack[0].src = (char *)config_str;
  ctx.stack[0].owns_src = false;
  ctx.stack[0].pos = 0;
  ctx.stack[0].len = strlen(config_str);
  if (initial_file_path) {
    int fd = open_via_dir_cache(initial_file_path, O_RDONLY, 0, false);
    if (fd >= 0) {
      struct stat st;
      if (fstat(fd, &st) == 0) {
        ctx.stack[0].dev = st.st_dev;
        ctx.stack[0].ino = st.st_ino;
      }
      close(fd);
    }
  }
  ctx.depth = 0;
  ctx.error_occurred = false;

  int res = parse_named_conf_internal(&ctx, config);

  config_lexer_cleanup(&ctx);
  if (res != 0 || ctx.error_occurred) {
    free_server_config_fields(config);
    return -1;
  }
  return 0;
}

int parse_named_conf(const char *config_str, server_config_t *config) {
  return parse_named_conf_ext(config_str, NULL, config);
}

#include "dns_config_parser.h"
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

static void skip_spaces_and_comments(token_ctx_t *ctx) {
  while (ctx->pos < ctx->len) {
    char c = ctx->src[ctx->pos];
    if (c == '\0') break;
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
      ctx->pos++;
    } else if (c == '#') {
      while (ctx->pos < ctx->len && ctx->src[ctx->pos] != '\n' && ctx->src[ctx->pos] != '\0')
        ctx->pos++;
    } else if (c == '/' && ctx->pos + 1 < ctx->len && ctx->src[ctx->pos + 1] == '/') {
      ctx->pos += 2;
      while (ctx->pos < ctx->len && ctx->src[ctx->pos] != '\n' && ctx->src[ctx->pos] != '\0')
        ctx->pos++;
    } else if (c == '/' && ctx->pos + 1 < ctx->len && ctx->src[ctx->pos + 1] == '*') {
      ctx->pos += 2;
      while (ctx->pos + 1 < ctx->len && !(ctx->src[ctx->pos] == '*' && ctx->src[ctx->pos + 1] == '/')) {
        if (ctx->src[ctx->pos] == '\0') break;
        ctx->pos++;
      }
      if (ctx->pos + 1 < ctx->len && ctx->src[ctx->pos] == '*' && ctx->src[ctx->pos + 1] == '/')
        ctx->pos += 2;
    } else {
      break;
    }
  }
}

conf_token_t get_next_token(token_ctx_t *ctx) {
  conf_token_t tok = {TOKEN_EOF, NULL};
  skip_spaces_and_comments(ctx);
  if (ctx->pos >= ctx->len || ctx->src[ctx->pos] == '\0')
    return tok;
  char c = ctx->src[ctx->pos];
  if (c == '{') {
    tok.type = TOKEN_LBRACE;
    ctx->pos++;
    return tok;
  }
  if (c == '}') {
    tok.type = TOKEN_RBRACE;
    ctx->pos++;
    return tok;
  }
  if (c == ';') {
    tok.type = TOKEN_SEMICOLON;
    ctx->pos++;
    return tok;
  }
  if (c == '"') {
    ctx->pos++;
    size_t start = ctx->pos;
    while (ctx->pos < ctx->len && ctx->src[ctx->pos] != '"' && ctx->src[ctx->pos] != '\0')
      ctx->pos++;
    size_t str_len = ctx->pos - start;
    if (str_len > 4096)
      str_len = 4096;
    tok.type = TOKEN_STRING;
    tok.value = malloc(str_len + 1);
    memcpy(tok.value, &ctx->src[start], str_len);
    tok.value[str_len] = '\0';
    if (ctx->pos < ctx->len && ctx->src[ctx->pos] == '"')
      ctx->pos++;
    return tok;
  }
  size_t start = ctx->pos;
  while (ctx->pos < ctx->len) {
    char nc = ctx->src[ctx->pos];
    if (nc == '\0' || nc == ' ' || nc == '\t' || nc == '\n' || nc == '\r' || nc == '{' ||
        nc == '}' || nc == ';' || nc == '#')
      break;
    if (nc == '/' && ctx->pos + 1 < ctx->len &&
        (ctx->src[ctx->pos + 1] == '/' || ctx->src[ctx->pos + 1] == '*'))
      break;
    ctx->pos++;
  }
  size_t str_len = ctx->pos - start;
  if (str_len == 0) {
    ctx->pos++;
    str_len = 1;
  }
  if (str_len > 4096)
    str_len = 4096;
  tok.type = TOKEN_STRING;
  tok.value = malloc(str_len + 1);
  memcpy(tok.value, &ctx->src[start], str_len);
  tok.value[str_len] = '\0';
  return tok;
}

void free_token(conf_token_t *tok) {
  if (tok->value) {
    free(tok->value);
    tok->value = NULL;
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
  for (int i = 0; i < zone->also_notify_count; i++)
    free(zone->also_notify[i].ip);
  free(zone->also_notify);
  free(zone->notify_source);
  for (int i = 0; i < zone->allow_transfer_count; i++)
    free(zone->allow_transfer[i]);
  free(zone->allow_transfer);
  free_rate_limit_config(&zone->rrl);
  free(zone);
}

char *read_entire_file(const char *path) {
  int fd = open_via_dir_cache(path, O_RDONLY, 0, false);
  if (fd < 0)
    return NULL;
  FILE *f = fdopen(fd, "rb");
  if (!f) {
    close(fd);
    return NULL;
  }
  fseek(f, 0, SEEK_END);
  long fsize = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (fsize < 0 || fsize > 256 * 1024 * 1024) {
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
    prefix = atoi(slash + 1);
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

static int parse_string_list(token_ctx_t *ctx, char ***list, int *count) {
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
    *list = realloc(*list, sizeof(char *) * (*count + 1));
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
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) {
    free_token(&tok);
    return -1;
  }
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
    *list = realloc(*list, sizeof(ip_port_t) * (*count + 1));
    (*list)[*count].ip = strdup(tok.value);
    (*list)[*count].port = 53;
    free_token(&tok);
    size_t saved_pos = ctx->pos;
    tok = get_next_token(ctx);
    if (tok.type == TOKEN_STRING && strcmp(tok.value, "port") == 0) {
      free_token(&tok);
      tok = get_next_token(ctx);
      if (tok.type == TOKEN_STRING)
        (*list)[*count].port = atoi(tok.value);
      else {
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      tok = get_next_token(ctx);
    } else {
      ctx->pos = saved_pos;
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

    if (strcmp(key, "responses-per-second") == 0) {
      rrl->responses_per_second = atoi(val);
    } else if (strcmp(key, "nxdomains-per-second") == 0) {
      rrl->nxdomains_per_second = atoi(val);
    } else if (strcmp(key, "errors-per-second") == 0) {
      rrl->errors_per_second = atoi(val);
    } else if (strcmp(key, "window") == 0) {
      rrl->window_seconds = atoi(val);
    } else if (strcmp(key, "slip") == 0) {
      rrl->slip = atoi(val);
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

int parse_named_conf(const char *config_str, server_config_t *config) {
  token_ctx_t ctx = {config_str, 0, strlen(config_str)};
  config->port = 53;
  config->bind_addresses = NULL;
  config->bind_address_count = 0;
  config->zones = NULL;
  config->user = NULL;
  config->group = NULL;
  config->send_extended_errors = true;
  zone_config_t *last_zone = NULL;
  while (1) {
    conf_token_t tok = get_next_token(&ctx);
    if (tok.type == TOKEN_EOF)
      break;
    if (tok.type != TOKEN_STRING) {
      free_token(&tok);
      return -1;
    }
    if (strcmp(tok.value, "options") == 0) {
      free_token(&tok);
      tok = get_next_token(&ctx);
      if (tok.type != TOKEN_LBRACE) {
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      while (1) {
        tok = get_next_token(&ctx);
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
          tok = get_next_token(&ctx);
          if (tok.type != TOKEN_STRING) {
            free(key);
            free_token(&tok);
            return -1;
          }
          char *val = strdup(tok.value);
          free_token(&tok);
          tok = get_next_token(&ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(key);
            free(val);
            free_token(&tok);
            return -1;
          }
          free_token(&tok);
          if (strcmp(key, "port") == 0) {
            int p = atoi(val);
            if (p > 0 && p <= 65535) config->port = p;
            free(val);
          } else if (strcmp(key, "user") == 0)
            config->user = val;
          else
            config->group = val;
        } else if (strcmp(key, "bind-address") == 0) {
          size_t saved_pos = ctx.pos;
          tok = get_next_token(&ctx);
          if (tok.type == TOKEN_LBRACE) {
            ctx.pos = saved_pos;
            free_token(&tok);
            if (parse_string_list(&ctx, &config->bind_addresses,
                                  &config->bind_address_count) != 0) {
              free(key);
              return -1;
            }
          } else if (tok.type == TOKEN_STRING) {
            config->bind_addresses =
                realloc(config->bind_addresses,
                        sizeof(char *) * (config->bind_address_count + 1));
            config->bind_addresses[config->bind_address_count++] =
                strdup(tok.value);
            free_token(&tok);
            tok = get_next_token(&ctx);
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
          if (parse_rate_limit_config(&ctx, &config->rrl) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "send-extended-errors") == 0) {
          tok = get_next_token(&ctx);
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
          tok = get_next_token(&ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(key);
            free_token(&tok);
            return -1;
          }
          free_token(&tok);
        } else
          skip_unknown_block(&ctx);
        free(key);
      }
      tok = get_next_token(&ctx);
      if (tok.type != TOKEN_SEMICOLON) {
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
    } else if (strcmp(tok.value, "zone") == 0) {
      free_token(&tok);
      tok = get_next_token(&ctx);
      if (tok.type != TOKEN_STRING) {
        free_token(&tok);
        return -1;
      }
      zone_config_t *zone = calloc(1, sizeof(zone_config_t));
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
      tok = get_next_token(&ctx);
      if (tok.type != TOKEN_LBRACE) {
        free_zone_config(zone);
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      while (1) {
        tok = get_next_token(&ctx);
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
          if (parse_ip_port_list(&ctx, &zone->masters, &zone->masters_count) !=
              0) {
            free(key);
            free_zone_config(zone);
            return -1;
          }
        } else if (strcmp(key, "also-notify") == 0) {
          if (parse_ip_port_list(&ctx, &zone->also_notify,
                                 &zone->also_notify_count) != 0) {
            free(key);
            free_zone_config(zone);
            return -1;
          }
        } else if (strcmp(key, "allow-transfer") == 0) {
          tok = get_next_token(&ctx);
          if (tok.type != TOKEN_LBRACE) {
            free(key); free_zone_config(zone); free_token(&tok); return -1;
          }
          free_token(&tok);
          
          int brace_depth = 1;
          bool in_negated_block = false;
          
          while (brace_depth > 0) {
            tok = get_next_token(&ctx);
            if (tok.type == TOKEN_EOF) {
              free(key); free_zone_config(zone); free_token(&tok); return -1;
            }
            if (tok.type == TOKEN_RBRACE) {
              brace_depth--;
              in_negated_block = false; // Exiting any block resets negated block state
              free_token(&tok);
              if (brace_depth > 0) {
                  // Inside a nested block, BIND requires a semicolon after the block '};'
                  tok = get_next_token(&ctx);
                  if (tok.type != TOKEN_SEMICOLON) { free(key); free_zone_config(zone); free_token(&tok); return -1; }
                  free_token(&tok);
              } else {
                  // End of the entire allow-transfer block, consume the outer semicolon '};'
                  tok = get_next_token(&ctx);
                  if (tok.type != TOKEN_SEMICOLON) { free(key); free_zone_config(zone); free_token(&tok); return -1; }
                  free_token(&tok);
              }
              continue;
            }
            if (tok.type == TOKEN_LBRACE) {
              brace_depth++;
              free_token(&tok);
              continue;
            }
            if (tok.type == TOKEN_SEMICOLON) {
              free_token(&tok);
              continue;
            }
            if (tok.type != TOKEN_STRING) {
              free(key); free_zone_config(zone); free_token(&tok); return -1;
            }
            
            if (strcmp(tok.value, "key") == 0) {
              free_token(&tok);
              tok = get_next_token(&ctx);
              if (tok.type != TOKEN_STRING) { free(key); free_zone_config(zone); free_token(&tok); return -1; }
              if (zone->tsig_key) free(zone->tsig_key);
              zone->tsig_key = strdup(tok.value);
              free_token(&tok);
              
              tok = get_next_token(&ctx);
              if (tok.type != TOKEN_SEMICOLON) { free(key); free_zone_config(zone); free_token(&tok); return -1; }
              free_token(&tok);
            } else if (strcmp(tok.value, "!") == 0) {
              free_token(&tok);
              tok = get_next_token(&ctx);
              if (tok.type == TOKEN_LBRACE) {
                  brace_depth++;
                  in_negated_block = true;
                  free_token(&tok);
                  continue;
              }
              if (tok.type != TOKEN_STRING) { free(key); free_zone_config(zone); free_token(&tok); return -1; }
              
              if (in_negated_block) {
                  if (strcmp(tok.value, "any") != 0) {
                      char *val = strdup(tok.value);
                      zone->allow_transfer = realloc(zone->allow_transfer, sizeof(char *) * (zone->allow_transfer_count + 1));
                      zone->allow_transfer[zone->allow_transfer_count++] = val;
                  }
              } else {
                  char buf[256];
                  snprintf(buf, sizeof(buf), "!%s", tok.value);
                  zone->allow_transfer = realloc(zone->allow_transfer, sizeof(char *) * (zone->allow_transfer_count + 1));
                  zone->allow_transfer[zone->allow_transfer_count++] = strdup(buf);
              }
              free_token(&tok);
              
              tok = get_next_token(&ctx);
              if (tok.type != TOKEN_SEMICOLON) { free(key); free_zone_config(zone); free_token(&tok); return -1; }
              free_token(&tok);
            } else {
              char *val = strdup(tok.value);
              free_token(&tok);
              
              // Handle combined "!ip"
              if (in_negated_block && val[0] == '!') {
                  // e.g. "!192.168.1.11" inside "!{ ... }" -> remove '!'
                  char *uncursed = strdup(val + 1);
                  free(val);
                  val = uncursed;
              }
              
              if (in_negated_block && strcmp(val, "any") == 0) {
                  free(val);
              } else {
                  zone->allow_transfer = realloc(zone->allow_transfer, sizeof(char *) * (zone->allow_transfer_count + 1));
                  zone->allow_transfer[zone->allow_transfer_count++] = val;
              }
              
              tok = get_next_token(&ctx);
              if (tok.type != TOKEN_SEMICOLON) { free(key); free_zone_config(zone); free_token(&tok); return -1; }
              free_token(&tok);
            }
          }
        } else if (strcmp(key, "type") == 0 || strcmp(key, "file") == 0 ||
                   strcmp(key, "tsig-key") == 0 ||
                   strcmp(key, "notify-source") == 0) {
          tok = get_next_token(&ctx);
          if (tok.type != TOKEN_STRING) {
            free(key);
            free_zone_config(zone);
            free_token(&tok);
            return -1;
          }
          char *val = strdup(tok.value);
          free_token(&tok);
          tok = get_next_token(&ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(key);
            free(val);
            free_zone_config(zone);
            free_token(&tok);
            return -1;
          }
          free_token(&tok);
          if (strcmp(key, "type") == 0)
            zone->type = val;
          else if (strcmp(key, "file") == 0)
            zone->file = val;
          else if (strcmp(key, "tsig-key") == 0)
            zone->tsig_key = val;
          else
            zone->notify_source = val;
        } else if (strcmp(key, "rate-limit") == 0) {
          if (parse_rate_limit_config(&ctx, &zone->rrl) != 0) {
            free(key);
            free_zone_config(zone);
            return -1;
          }
        } else
          skip_unknown_block(&ctx);
        free(key);
      }
      tok = get_next_token(&ctx);
      if (tok.type != TOKEN_SEMICOLON) {
        free_zone_config(zone);
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      if (!config->zones)
        config->zones = zone;
      else
        last_zone->next = zone;
      last_zone = zone;
    } else if (strcmp(tok.value, "key") == 0) {
      free_token(&tok);
      tok = get_next_token(&ctx);
      if (tok.type != TOKEN_STRING) {
        free_token(&tok);
        return -1;
      }
      tsig_key_t *tsig = calloc(1, sizeof(tsig_key_t));
      tsig->name = strdup(tok.value);
      free_token(&tok);
      tok = get_next_token(&ctx);
      if (tok.type != TOKEN_LBRACE) {
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      while (1) {
        tok = get_next_token(&ctx);
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
          tok = get_next_token(&ctx);
          if (tok.type != TOKEN_STRING) {
            free(key_prop);
            free_token(&tok);
            return -1;
          }
          char *val = strdup(tok.value);
          free_token(&tok);
          tok = get_next_token(&ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(key_prop);
            free(val);
            free_token(&tok);
            return -1;
          }
          free_token(&tok);
          if (strcmp(key_prop, "algorithm") == 0)
            tsig->algorithm = val;
          else {
            tsig->secret = val;
            size_t slen = strlen(tsig->secret);
            size_t decoded_upper_bound = (slen / 4) * 3;
            if (slen == 0 || decoded_upper_bound > sizeof(tsig->secret_decoded)) {
              syslog(LOG_ERR, "[Config] secret too long for algorithm (decodes to %zu bytes, max %zu)", decoded_upper_bound, sizeof(tsig->secret_decoded));
              fprintf(stderr, "[ERROR] secret too long for algorithm\n");
              free(key_prop);
              free(val);
              tsig->secret = NULL;
              free_token(&tok);
              return -1;
            }
            int len = EVP_DecodeBlock(tsig->secret_decoded,
                                      (const unsigned char *)tsig->secret,
                                      slen);
            if (len < 0) {
              free(key_prop);
              free(val);
              tsig->secret = NULL;
              free_token(&tok);
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
          skip_unknown_block(&ctx);
        free(key_prop);
      }
      tok = get_next_token(&ctx);
      if (tok.type != TOKEN_SEMICOLON) {
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      tsig->next = config->keys;
      config->keys = tsig;
    } else if (strcmp(tok.value, "control-channel") == 0) {
      free_token(&tok);
      tok = get_next_token(&ctx);
      if (tok.type != TOKEN_LBRACE) {
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      config->control.enabled = true;
      while (1) {
        tok = get_next_token(&ctx);
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
          tok = get_next_token(&ctx);
          if (tok.type != TOKEN_STRING) {
            free(key_prop);
            free_token(&tok);
            return -1;
          }
          char *val = strdup(tok.value);
          free_token(&tok);
          tok = get_next_token(&ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(key_prop);
            free(val);
            free_token(&tok);
            return -1;
          }
          free_token(&tok);
          if (strcmp(key_prop, "algorithm") == 0)
            config->control.algorithm = val;
          else {
            config->control.secret = val;
            size_t slen = strlen(config->control.secret);
            size_t decoded_upper_bound = (slen / 4) * 3;
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
          skip_unknown_block(&ctx);
        free(key_prop);
      }
      tok = get_next_token(&ctx);
      if (tok.type != TOKEN_SEMICOLON) {
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
    } else if (strcmp(tok.value, "logging") == 0) {
      free_token(&tok);
      tok = get_next_token(&ctx);
      if (tok.type != TOKEN_LBRACE) {
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      while (1) {
        tok = get_next_token(&ctx);
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
          tok = get_next_token(&ctx);
          if (tok.type != TOKEN_STRING) {
            free(dir);
            free_token(&tok);
            return -1;
          }
          log_channel_t *ch = calloc(1, sizeof(log_channel_t));
          ch->name = strdup(tok.value);
          free_token(&tok);
          ch->fd = -1;
          pthread_mutex_init(&ch->lock, NULL);
          tok = get_next_token(&ctx);
          if (tok.type != TOKEN_LBRACE) {
            free(dir);
            free_token(&tok);
            return -1;
          }
          free_token(&tok);
          while (1) {
            tok = get_next_token(&ctx);
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
              tok = get_next_token(&ctx);
              if (tok.type != TOKEN_STRING) {
                free(opt);
                free_token(&tok);
                return -1;
              }
              ch->file_path = strdup(tok.value);
              free_token(&tok);
              while (1) {
                tok = get_next_token(&ctx);
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
                  tok = get_next_token(&ctx);
                  if (tok.type == TOKEN_STRING)
                    ch->versions = atoi(tok.value);
                  free_token(&tok);
                } else if (tok.type == TOKEN_STRING &&
                           strcmp(tok.value, "size") == 0) {
                  free_token(&tok);
                  tok = get_next_token(&ctx);
                  if (tok.type == TOKEN_STRING) {
                    size_t mult = 1;
                    size_t len = strlen(tok.value);
                    if (len > 0) {
                      char last = tok.value[len - 1];
                      if (last == 'M' || last == 'm')
                        mult = 1024 * 1024;
                      else if (last == 'K' || last == 'k')
                        mult = 1024;
                      else if (last == 'G' || last == 'g')
                        mult = 1024 * 1024 * 1024;
                      ch->size_limit = strtoull(tok.value, NULL, 10) * mult;
                    }
                  }
                  free_token(&tok);
                } else if (tok.type == TOKEN_STRING &&
                           strcmp(tok.value, "suffix") == 0) {
                  free_token(&tok);
                  tok = get_next_token(&ctx);
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
              tok = get_next_token(&ctx);
              bool val =
                  (tok.type == TOKEN_STRING && strcmp(tok.value, "yes") == 0);
              free_token(&tok);
              tok = get_next_token(&ctx);
              if (tok.type == TOKEN_SEMICOLON)
                free_token(&tok);
              if (strcmp(opt, "print-time") == 0)
                ch->print_time = val;
              else if (strcmp(opt, "print-category") == 0)
                ch->print_category = val;
              else
                ch->print_severity = val;
            } else
              skip_unknown_block(&ctx);
            free(opt);
          }
          tok = get_next_token(&ctx);
          if (tok.type == TOKEN_SEMICOLON)
            free_token(&tok);
          ch->next = config->logging.channels;
          config->logging.channels = ch;
        } else if (strcmp(dir, "category") == 0) {
          tok = get_next_token(&ctx);
          if (tok.type != TOKEN_STRING) {
            free(dir);
            free_token(&tok);
            return -1;
          }
          char *cat_name = strdup(tok.value);
          free_token(&tok);
          tok = get_next_token(&ctx);
          if (tok.type == TOKEN_LBRACE) {
            free_token(&tok);
            tok = get_next_token(&ctx);
            if (strcmp(cat_name, "queries") == 0 && tok.type == TOKEN_STRING)
              config->logging.queries_channel_name = strdup(tok.value);
            else if (strcmp(cat_name, "responses") == 0 && tok.type == TOKEN_STRING)
              config->logging.responses_channel_name = strdup(tok.value);
            free_token(&tok);
            tok = get_next_token(&ctx);
            if (tok.type == TOKEN_SEMICOLON)
              free_token(&tok);
            tok = get_next_token(&ctx);
            if (tok.type == TOKEN_RBRACE)
              free_token(&tok);
          }
          free(cat_name);
          tok = get_next_token(&ctx);
          if (tok.type == TOKEN_SEMICOLON)
            free_token(&tok);
        } else
          skip_unknown_block(&ctx);
        free(dir);
      }
      tok = get_next_token(&ctx);
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
      }
    } else {
      free_token(&tok);
      skip_unknown_block(&ctx);
    }
  }
  return 0;
}


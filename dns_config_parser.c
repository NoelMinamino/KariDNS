#include "dns_config_parser.h"
#include <openssl/crypto.h>
#include "dns_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include "dns_log.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <limits.h>
#include <errno.h>
#include <stdarg.h>
#include <pwd.h>
#include <grp.h>
#include "dns_wire.h"
#include "dns_tsig_acl.h"

static int hex_nibble_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static void *safe_realloc_or_die(void *ptr, size_t size) {
  if (size == 0) {
    free(ptr);
    return NULL;
  }
  void *p = realloc(ptr, size);
  if (!p) {
    syslog(LOG_CRIT, "[Config] Out of memory during config parse (requested %zu bytes)", size);
#ifdef KARIDNS_UNIT_TEST
    return NULL;
#else
    exit(1);
#endif
  }
  return p;
}

static void *safe_calloc_or_die(size_t nmemb, size_t size) {
  if (nmemb == 0 || size == 0) {
    return NULL;
  }
  void *p = calloc(nmemb, size);
  if (!p) {
    syslog(LOG_CRIT, "[Config] Out of memory during config parse (requested %zu bytes)", nmemb * size);
#ifdef KARIDNS_UNIT_TEST
    return NULL;
#else
    exit(1);
#endif
  }
  return p;
}

void *safe_realloc_or_die_test_wrapper(void *ptr, size_t size) {
  return safe_realloc_or_die(ptr, size);
}

void *safe_calloc_or_die_test_wrapper(size_t nmemb, size_t size) {
  return safe_calloc_or_die(nmemb, size);
}

#define APPEND_STR(arr, cnt, val) \
    do { \
        char *_val_dup = (val); \
        if (!_val_dup) { \
            if (ctx) ctx->error_occurred = true; \
            return -1; \
        } \
        char **_new_arr = safe_realloc_or_die((arr), sizeof(char *) * ((cnt) + 1)); \
        if (!_new_arr) { \
            free(_val_dup); \
            if (ctx) ctx->error_occurred = true; \
            return -1; \
        } \
        (arr) = _new_arr; \
        (arr)[(cnt)++] = _val_dup; \
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
    if (!tok.value) {
      tok.type = TOKEN_EOF;
      return tok;
    }
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
  if (!tok.value) {
    tok.type = TOKEN_EOF;
    return tok;
  }
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

    if (tok.type == TOKEN_EOF || (tok.type == TOKEN_STRING && !tok.value)) {
      if (tok.type == TOKEN_STRING && !tok.value) {
        ctx->error_occurred = true;
        tok.type = TOKEN_EOF;
      }
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

    if (tok.type == TOKEN_STRING && tok.value && !tok.is_quoted && strcmp(tok.value, "include") == 0) {
      free_token(&tok);
      if (ctx->no_include) { /* B7a: settings text of a DB zone: no file is ever opened for it */
        snprintf(ctx->restricted_err, sizeof(ctx->restricted_err), "'include' is not allowed in the settings of a database zone");
        ctx->error_occurred = true;
        return (conf_token_t){TOKEN_EOF, NULL, false};
      }

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

      /* A relative name is read from options { directory } when there is one (BIND 9.20 ARM: every relative path in the configuration
       * is relative to it), else from the directory of the file that contains the include (what this server has always done). */
      const char *parent_path = frame->file_path;
      char *base_dir = ctx->directory ? strdup(ctx->directory) : parent_path ? get_base_dir(parent_path) : strdup(".");
      char resolved[PATH_MAX];
      bool was_rel = false;
      if (tok_file.value[0] == '/') {
        snprintf(resolved, sizeof(resolved), "%s", tok_file.value);
      } else {
        was_rel = true;
        ctx->rel_includes++;
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

      char *dup_path = strdup(resolved);
      if (!dup_path) {
        free(content);
        ctx->error_occurred = true;
        return (conf_token_t){TOKEN_EOF, NULL, false};
      }
      ctx->depth++;
      ctx->stack[ctx->depth].file_path = dup_path;
      ctx->stack[ctx->depth].src = content;
      ctx->stack[ctx->depth].owns_src = true;
      ctx->stack[ctx->depth].pos = 0;
      ctx->stack[ctx->depth].len = strlen(content);
      ctx->stack[ctx->depth].dev = inc_dev;
      ctx->stack[ctx->depth].ino = inc_ino;
      ctx->stack[ctx->depth].via_rel = was_rel;

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
  if (rrl->exempt_clients_parsed) {
    free(rrl->exempt_clients_parsed);
    rrl->exempt_clients_parsed = NULL;
  }
  rrl->exempt_clients_count = 0;
}

const zone_ext_t zone_ext_default = {0}; /* 全ゼロ = すべて既定 */

zone_ext_t *zone_ext_mut(zone_config_t *z) {
  if (!z->ext) z->ext = calloc(1, sizeof(*z->ext));
  return z->ext;
}

static void notify_targets_free(notify_target_t *l, int n);
static void remote_lists_free(remote_list_t *r);

static void acl_set_free(acl_set_t *s) {
  aml_unref(s->query);
  aml_unref(s->query_on);
  aml_unref(s->transfer);
  aml_unref(s->update);
  aml_unref(s->notify);
  aml_unref(s->match);
  memset(s, 0, sizeof(*s));
}

static void acl_set_copy(acl_set_t *d, const acl_set_t *s) {
  d->query = aml_ref(s->query);
  d->query_on = aml_ref(s->query_on);
  d->transfer = aml_ref(s->transfer);
  d->update = aml_ref(s->update);
  d->notify = aml_ref(s->notify);
  d->match = aml_ref(s->match);
}

static void xo_free_fields(xfr_opts_t *xo);
static void catz_names_free(char **names, int count);

/* everything x points to (not x itself: a zone_ext_shared_t embeds it) */
static void free_zone_ext_fields(zone_ext_t *x) {
  if (!x)
    return;
  acl_set_free(&x->acl);
  notify_targets_free(x->masters, x->masters_count);
  if (x->masters_parsed) {
    free(x->masters_parsed);
    x->masters_parsed = NULL;
  }
  free(x->tsig_key);
  for (int i = 0; i < x->tsig_keys_count; i++)
    free(x->tsig_keys[i]);
  free(x->tsig_keys);
  notify_targets_free(x->also_notify, x->also_notify_count);
  free(x->notify_source);
  if (x->xo) {
    xo_free_fields(x->xo);
    free(x->xo);
    x->xo = NULL;
  }
  for (int i = 0; i < x->alias_resolvers_count; i++)
    free(x->alias_resolvers[i].ip);
  free(x->alias_resolvers);
  for (int i = 0; i < x->allow_transfer_count; i++)
    free(x->allow_transfer[i]);
  free(x->allow_transfer);
  if (x->allow_transfer_parsed) {
    free(x->allow_transfer_parsed);
    x->allow_transfer_parsed = NULL;
  }
  for (int i = 0; i < x->allow_update_count; i++)
    free(x->allow_update[i]);
  free(x->allow_update);
  if (x->allow_update_parsed) {
    free(x->allow_update_parsed);
    x->allow_update_parsed = NULL;
  }
  free(x->program_path);
  for (int i = 0; i < x->program_args_count; i++)
    free(x->program_args[i]);
  free(x->program_args);
  free(x->program_user);
  for (int i = 0; i < x->forwarders_count; i++)
    free(x->forwarders[i].ip);
  free(x->forwarders);
  free(x->file_format);
  free(x->upd_policy);
  free_rate_limit_config(&x->rrl);
  if (x->ecs_tags) {
    for (int i = 0; i < x->ecs_tag_count; i++) {
      free(x->ecs_tags[i].tag);
      for (int j = 0; j < x->ecs_tags[i].cidr_count; j++) {
        free(x->ecs_tags[i].cidrs[j].cidr);
      }
      free(x->ecs_tags[i].cidrs);
    }
    free(x->ecs_tags);
    x->ecs_tags = NULL;
    x->ecs_tag_count = 0;
  }
  if (x->location_tags) {
    for (int i = 0; i < x->location_tag_count; i++) {
      free(x->location_tags[i].tag);
      for (int j = 0; j < x->location_tags[i].cidr_count; j++) {
        free(x->location_tags[i].cidrs[j].cidr);
      }
      free(x->location_tags[i].cidrs);
    }
    free(x->location_tags);
    x->location_tags = NULL;
    x->location_tag_count = 0;
  }
  if (x->ecs_trusted_resolvers) {
    for (int i = 0; i < x->ecs_trusted_resolvers_count; i++) {
      free(x->ecs_trusted_resolvers[i]);
    }
    free(x->ecs_trusted_resolvers);
    x->ecs_trusted_resolvers = NULL;
    x->ecs_trusted_resolvers_count = 0;
  }
  if (x->ecs_trusted_resolvers_parsed) {
    free(x->ecs_trusted_resolvers_parsed);
    x->ecs_trusted_resolvers_parsed = NULL;
  }
}

static void free_zone_ext(zone_ext_t *x) {
  if (!x)
    return;
  free_zone_ext_fields(x);
  free(x);
}

zone_ext_shared_t *zone_ext_shared_ref(zone_ext_shared_t *s) {
  if (s) atomic_fetch_add_explicit(&s->refs, 1, memory_order_relaxed);
  return s;
}

void zone_ext_shared_unref(zone_ext_shared_t *s) {
  if (!s)
    return;
  if (atomic_fetch_sub_explicit(&s->refs, 1, memory_order_acq_rel) == 1) {
    free_zone_ext_fields(&s->ext);
    free(s->key);
    free(s);
  }
}

void free_zone_config(zone_config_t *zone) {
  if (!zone)
    return;
  free(zone->domain);
  free(zone->type);
  free(zone->file);
  if (zone->ext_shared)
    zone_ext_shared_unref((zone_ext_shared_t *)zone->ext); /* ext is the first member of the shared object */
  else
    free_zone_ext(zone->ext);
  free(zone);
}

void zone_cfg_index_free(zone_cfg_index_t *ix) {
  if (!ix) return;
  free(ix->slots);
  memset(ix, 0, sizeof(*ix));
}

static zone_config_t *zone_cfg_index_find(const zone_cfg_index_t *ix, const char *domain) {
  for (uint32_t i = dns_name_hash_ci(domain) & ix->mask; ix->slots[i]; i = (i + 1) & ix->mask) {
    if (domain_names_match_ci(ix->slots[i]->domain, domain)) return ix->slots[i];
  }
  return NULL;
}

int zone_cfg_index_insert(zone_cfg_index_t *ix, zone_config_t *z, zone_config_t **dup) {
  if (dup) *dup = NULL;
  if (!z || !z->domain) return 0;
  if (ix->slots) {
    zone_config_t *found = zone_cfg_index_find(ix, z->domain);
    if (found) {
      if (dup) *dup = found;
      return 1;
    }
  }
  /* 使用率を 1/2 以下に保つ (線形探索の探索長を短くする) */
  if (!ix->slots || (size_t)(ix->count + 1) * 2 > (size_t)ix->mask + 1) {
    size_t cap = ix->slots ? ((size_t)ix->mask + 1) * 2 : 16;
    if (cap > UINT32_MAX) return -1;
    zone_config_t **slots = calloc(cap, sizeof(*slots));
    if (!slots) return -1;
    uint32_t mask = (uint32_t)(cap - 1);
    for (uint32_t k = 0; ix->slots && k <= ix->mask; k++) {
      zone_config_t *old = ix->slots[k];
      if (!old) continue;
      uint32_t i = dns_name_hash_ci(old->domain) & mask;
      while (slots[i]) i = (i + 1) & mask;
      slots[i] = old;
    }
    free(ix->slots);
    ix->slots = slots;
    ix->mask = mask;
  }
  uint32_t i = dns_name_hash_ci(z->domain) & ix->mask;
  while (ix->slots[i]) i = (i + 1) & ix->mask;
  ix->slots[i] = z;
  ix->count++;
  return 0;
}

zone_config_t *view_find_zone_config(const view_config_t *v, const char *domain) {
  if (!v || !domain) return NULL;
  if (v->zone_index.slots) return zone_cfg_index_find(&v->zone_index, domain);
  for (zone_config_t *z = v->zones; z; z = z->next) {
    if (domain_names_match_ci(z->domain, domain)) return z;
  }
  return NULL;
}

zone_config_t *config_find_zone_any_view(const server_config_t *cfg, const char *domain) {
  if (!cfg || !domain) return NULL;
  if (cfg->views) {
    for (const view_config_t *v = cfg->views; v; v = v->next) {
      zone_config_t *z = view_find_zone_config(v, domain);
      if (z) return z;
    }
    return NULL;
  }
  for (zone_config_t *z = cfg->zones; z; z = z->next) {
    if (domain_names_match_ci(z->domain, domain)) return z;
  }
  return NULL;
}

static void free_str_list(char **list, int count) {
  for (int i = 0; i < count; i++) free(list[i]);
  free(list);
}

static void free_database_config(database_config_t *db) {
  free(db->driver);
  free(db->database_file);
  free(db->conninfo_file);
  free(db->schema);
  free(db->loader_user);
  free(db->loader_group);
  free(db->loader_path);
  free_str_list(db->acl_ceiling, db->acl_ceiling_count);
  free(db->acl_ceiling_parsed);
  free_str_list(db->acl_ceiling_keys, db->acl_ceiling_keys_count);
  free(db->server_id);
  free_str_list(db->alias_resolver, db->alias_resolver_count);
  memset(db, 0, sizeof(*db));
}

static void free_view_db_fields(view_config_t *view) {
  free(view->database_file);
  free(view->database_schema);
  view->database_file = view->database_schema = NULL;
  view->database_none = false;
}

static void tsig_keys_free(tsig_key_t *k) {
  while (k) {
    tsig_key_t *next_k = k->next;
    free(k->name);
    free(k->algorithm);
    free(k->secret);
    OPENSSL_cleanse(k->secret_decoded, sizeof(k->secret_decoded));
    free(k);
    k = next_k;
  }
}

static void server_stmts_free(server_stmt_t *s) {
  while (s) {
    server_stmt_t *next = s->next;
    free(s->key);
    xo_free_fields(&s->xo);
    free(s);
    s = next;
  }
}

static void free_partial_view(view_config_t *view) {
  if (!view) return;
  zone_cfg_index_free(&view->zone_index);
  free_view_db_fields(view);
  catz_names_free(view->catz_names, view->catz_count);
  if (view->name) free(view->name);
  acl_set_free(&view->acl);
  xo_free_fields(&view->xo);
  tsig_keys_free(view->keys);
  server_stmts_free(view->servers);
  notify_targets_free(view->also_notify, view->also_notify_count);
  for (int i = 0; i < view->match_clients_count; i++) free(view->match_clients[i]);
  if (view->match_clients) free(view->match_clients);
  if (view->match_clients_parsed) {
    free(view->match_clients_parsed);
    view->match_clients_parsed = NULL;
  }
  zone_config_t *z = view->zones;
  while (z) {
    zone_config_t *next = z->next;
    free_zone_config(z);
    z = next;
  }
  free(view);
}

/* [T7] 定義済み TSIG キーリストを線形探索するヘルパー。
 * 鍵名は DNS 名なので大文字小文字と末尾のドットを区別しない (D-03。重複の検出と同じ規則) */
static bool key_name_is_defined(const tsig_key_t *keys, const char *name) {
  if (!name) return false;
  for (const tsig_key_t *k = keys; k; k = k->next) {
    if (k->name && domain_names_match_ci(k->name, name)) return true;
  }
  return false;
}

/* Is the key usable where the statement being checked is?  A key is global, or it is in the view whose statements are being checked
 * (ctx->scope_keys; BIND bin/named/tsigconf.c: the ring of a view is the global keys plus the view's own). */
static bool key_is_defined(const token_ctx_t *ctx, const server_config_t *cfg, const char *name) {
  return key_name_is_defined(cfg->keys, name) || (ctx && key_name_is_defined(ctx->scope_keys, name));
}

/* D-22: BIND の組み込み ACL 名。any と none は要素として使える。localhost と localnets は
 * インターフェイスのアドレスに依存し、サンドボックス内のリロードで求め直せないので未対応 */
static bool acl_name_is_builtin(const char *name) {
  return strcasecmp(name, "any") == 0 || strcasecmp(name, "none") == 0 ||
         strcasecmp(name, "localhost") == 0 || strcasecmp(name, "localnets") == 0;
}

/* アドレス、プレフィックス、any、none のどれか (none は何にも一致しない) */
static bool acl_entry_is_address(const char *t) {
  if (strcmp(t, "any") == 0 || strcmp(t, "none") == 0) return true;
  cidr_entry_t e;
  return cidr_entry_parse(&e, t);
}

typedef enum { ACL_USE_TRANSFER, ACL_USE_UPDATE, ACL_USE_ADDRESS } acl_use_t;

static int acl_reject(token_ctx_t *ctx, const char *where, const char *entry, const char *why) {
  syslog(LOG_ERR, "[Config] %s: entry '%s' %s", where, entry, why);
  fprintf(stderr, "[ERROR] %s: entry '%s' %s\n", where, entry, why);
  if (ctx) ctx->error_occurred = true;
  return -1;
}

/* src の要素を out へ展開する。名前付き ACL の参照は同じ内容を波括弧で書いたものとして
 * 展開する (否定は parse_acl_list() の "! { ... }" と同じ規則: 各要素を否定し、二重否定は肯定)。
 * key 要素は allow-transfer では keys_out へ、allow-update では鍵名として out へ入れる。 */
static int acl_expand_into(token_ctx_t *ctx, const server_config_t *cfg, const char *where, acl_use_t use,
                           char *const *src, int src_count, bool negate, int depth,
                           char ***out, int *out_count, char ***keys_out, int *keys_count) {
  for (int i = 0; i < src_count; i++) {
    const char *e = src[i];
    if (!e) continue;
    bool neg = negate != (e[0] == '!');
    const char *t = (e[0] == '!') ? e + 1 : e;
    if (t[0] == ACL_KEY_MARK) {
      const char *kname = t + 1;
      if (neg) return acl_reject(ctx, where, kname, "is a negated key, which is not supported");
      if (!key_is_defined(ctx, cfg, kname))
        return acl_reject(ctx, where, kname, "names a key that is not defined in any key {} block");
      if (use == ACL_USE_ADDRESS) return acl_reject(ctx, where, kname, "is a key; only addresses can be used here");
      if (use == ACL_USE_TRANSFER) {
        APPEND_STR(*keys_out, *keys_count, strdup(kname));
      } else {
        APPEND_STR(*out, *out_count, strdup(kname));
      }
      continue;
    }
    if (acl_entry_is_address(t)) {
      if (negate && strcmp(t, "any") == 0) continue; /* "! { any; }" の any は parse_acl_list() と同じく捨てる */
      size_t tlen = strlen(t);
      char *v = malloc(tlen + 2);
      if (!v) { if (ctx) ctx->error_occurred = true; return -1; }
      snprintf(v, tlen + 2, "%s%s", neg ? "!" : "", t);
      APPEND_STR(*out, *out_count, v);
      continue;
    }
    if (strcasecmp(t, "localhost") == 0 || strcasecmp(t, "localnets") == 0) {
      /* the flat lists get the interface addresses (localhost) or their networks (localnets) of the start-up snapshot; allow-query,
       * allow-transfer, allow-update and allow-notify evaluate the names at run time (dns_tsig_acl.c) */
      const aml_iface_t *ifs;
      size_t nif = aml_get_interfaces(&ifs);
      bool nets = strcasecmp(t, "localnets") == 0;
      for (size_t k = 0; k < nif; k++) {
        char ip[INET6_ADDRSTRLEN];
        if (!inet_ntop(ifs[k].family, ifs[k].addr, ip, sizeof(ip))) continue;
        int prefix = ifs[k].family == AF_INET ? 32 : 128;
        if (nets) {
          prefix = 0;
          for (int b = 0; b < (ifs[k].family == AF_INET ? 4 : 16); b++) {
            uint8_t m = ifs[k].mask[b];
            if (m == 0xff) { prefix += 8; continue; }
            while (m & 0x80) { prefix++; m = (uint8_t)(m << 1); }
            break;
          }
        }
        char ent[INET6_ADDRSTRLEN + 8];
        snprintf(ent, sizeof(ent), "%s%s/%d", neg ? "!" : "", ip, prefix);
        APPEND_STR(*out, *out_count, strdup(ent));
      }
      continue;
    }
    if (acl_name_is_builtin(t))
      return acl_reject(ctx, where, t, "is not supported (list the addresses instead)");
    const acl_def_t *acl = NULL;
    for (const acl_def_t *a = cfg->acls; a; a = a->next)
      if (strcasecmp(a->name, t) == 0) { acl = a; break; }
    if (acl) {
      if (depth >= MAX_INCLUDE_DEPTH) return acl_reject(ctx, where, t, "nests acl references too deeply (loop?)");
      if (acl_expand_into(ctx, cfg, where, use, acl->entries, acl->count, neg, depth + 1,
                          out, out_count, keys_out, keys_count) != 0)
        return -1;
      continue;
    }
    /* allow-update は従来どおり鍵名だけの要素も受け付ける (key "name" と同じ意味) */
    if (use == ACL_USE_UPDATE && !neg && key_is_defined(ctx, cfg, t)) {
      APPEND_STR(*out, *out_count, strdup(t));
      continue;
    }
    return acl_reject(ctx, where, e, use == ACL_USE_UPDATE
                                         ? "is not an address, prefix, any, none, a defined acl or a defined key"
                                         : "is not an address, prefix, any, none or a defined acl");
  }
  return 0;
}

/* 1つの ACL フィールドを展開して置き換え、parsed を作り直す */
static int acl_expand_field(token_ctx_t *ctx, const server_config_t *cfg, const char *where, acl_use_t use,
                            char ***list, int *count, acl_entry_t **parsed, char ***keys, int *keys_count) {
  if (*count <= 0) return 0;
  char **out = NULL;
  int out_count = 0;
  int rc = acl_expand_into(ctx, cfg, where, use, *list, *count, false, 0, &out, &out_count, keys, keys_count);
  for (int i = 0; i < *count; i++) free((*list)[i]);
  free(*list);
  *list = out;
  *count = out_count;
  if (rc != 0) return -1;
  if (parsed) {
    free(*parsed);
    *parsed = acl_list_parse(*list, *count);
  }
  return 0;
}

/* ---- resolving the BIND address match lists once the whole file is read ---- */

static void aml_report(token_ctx_t *ctx, const char *loc, const char *what, const char *fmt, ...) __attribute__((format(printf, 4, 5)));
static void aml_report(token_ctx_t *ctx, const char *loc, const char *what, const char *fmt, ...) {
  char msg[300];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);
  if (loc) {
    syslog(LOG_ERR, "[Config] %s: %s: %s", loc, what, msg);
    fprintf(stderr, "[ERROR] %s: %s: %s\n", loc, what, msg);
  } else {   /* a problem of the configuration as a whole (an acl that contains itself, an option that does not go with a list) */
    syslog(LOG_ERR, "[Config] %s: %s", what, msg);
    fprintf(stderr, "[ERROR] %s: %s\n", what, msg);
  }
  if (ctx) ctx->error_occurred = true;
}

static int acl_def_resolve(token_ctx_t *ctx, server_config_t *cfg, acl_def_t *a, const char *loc);

/* Names become their lists (an acl block, localhost / localnets were recognised when read), keys must exist, and the flags and the
 * depth of every list are set.  bare_keys: a name that is no acl but a defined key means `key <name>` (what allow-update has always
 * accepted).  A list that is already resolved (the list of an acl block) is not touched twice. */
static int aml_resolve(token_ctx_t *ctx, server_config_t *cfg, aml_t *l, const char *what, bool bare_keys, int depth) {
  if (depth > AML_MAX_DEPTH) {
    aml_report(ctx, NULL, what, "address match lists are nested too deeply");
    return -1;
  }
  l->has_addr = l->has_key = l->has_neg_key = false;
  l->depth = 1;
  for (int i = 0; i < l->count; i++) {
    aml_elem_t *e = &l->elems[i];
    if (e->kind == AML_E_NAME) {
      acl_def_t *a = NULL;
      for (acl_def_t *d = cfg->acls; d; d = d->next)
        if (strcasecmp(d->name, e->text) == 0) { a = d; break; }
      if (a) {
        if (acl_def_resolve(ctx, cfg, a, e->loc) != 0) return -1;
        e->kind = AML_E_LIST;
        e->u.list = aml_ref(a->aml);
      } else if (bare_keys && !e->neg && key_is_defined(ctx, cfg, e->text)) {
        e->kind = AML_E_KEY;
      } else {
        aml_report(ctx, e->loc, what, "entry '%.64s' is not an address, prefix, any, none, localhost, localnets or a defined acl%s", e->text,
                   bare_keys ? " or key" : "");
        return -1;
      }
    } else if (e->kind == AML_E_KEY) {
      if (!key_is_defined(ctx, cfg, e->text)) {
        aml_report(ctx, e->loc, what, "key '%.64s' is not defined in any key {} block", e->text);
        return -1;
      }
    } else if (e->kind == AML_E_LIST && e->u.list->depth == 0) {
      if (aml_resolve(ctx, cfg, e->u.list, what, bare_keys, depth + 1) != 0) return -1;
    }
    free(e->loc);
    e->loc = NULL;
    switch (e->kind) {
    case AML_E_KEY:
      l->has_key = true;
      if (e->neg) l->has_neg_key = true;
      break;
    case AML_E_LIST: {
      const aml_t *c = e->u.list;
      if (c->has_addr) l->has_addr = true;
      if (c->has_key) l->has_key = true;
      if (c->has_neg_key || (e->neg && c->has_key)) l->has_neg_key = true;
      if (c->depth + 1 > l->depth) l->depth = (uint8_t)(c->depth + 1);
      break;
    }
    default:
      l->has_addr = true;
      break;
    }
  }
  if (l->depth > AML_MAX_DEPTH) {
    aml_report(ctx, NULL, what, "address match lists are nested too deeply");
    return -1;
  }
  return 0;
}

static int acl_def_resolve(token_ctx_t *ctx, server_config_t *cfg, acl_def_t *a, const char *loc) {
  if (a->state == 2) return 0;
  char what[DNS_NAME_TEXT_SIZE + 16];
  snprintf(what, sizeof(what), "acl '%.255s'", a->name);
  if (a->state == 1) {
    aml_report(ctx, loc, what, "refers to itself (an acl cannot contain itself, directly or through other acl blocks)");
    return -1;
  }
  a->state = 1;
  int rc = a->aml ? aml_resolve(ctx, cfg, a->aml, what, true, 0) : 0;
  a->state = 2;
  return rc;
}

static int acl_set_resolve(token_ctx_t *ctx, server_config_t *cfg, acl_set_t *s, const char *label) {
  static const char *const names[6] = { "allow-query", "allow-query-on", "allow-transfer", "allow-update", "allow-notify", "match-clients" };
  aml_t *const lists[6] = { s->query, s->query_on, s->transfer, s->update, s->notify, s->match };
  for (int i = 0; i < 6; i++) {
    if (!lists[i]) continue;
    char what[DNS_NAME_TEXT_SIZE + 64];
    snprintf(what, sizeof(what), "%s %s", label, names[i]);
    if (aml_resolve(ctx, cfg, lists[i], what, i == AML_ACL_UPDATE, 0) != 0) return -1;
  }
  return 0;
}

/* After the parse: every list resolved, acl_query_active set, and transfer-acl-match / update-acl-match any / all refused where the
 * list that applies has a negated key (the flat evaluation of those settings cannot say "not signed with k"). */
static int resolve_all_acl_lists(token_ctx_t *ctx, server_config_t *cfg) {
  for (acl_def_t *a = cfg->acls; a; a = a->next)
    if (acl_def_resolve(ctx, cfg, a, NULL) != 0) return -1;
  if (acl_set_resolve(ctx, cfg, &cfg->acl, "options") != 0) return -1;
  cfg->acl_query_active = cfg->acl.query || cfg->acl.query_on;
  for (view_config_t *v = cfg->views; v; v = v->next) {
    char label[KARIDNS_VIEW_NAME_MAX + 16];
    snprintf(label, sizeof(label), "view '%s'", v->name);
    ctx->scope_keys = v->keys;
    if (acl_set_resolve(ctx, cfg, &v->acl, label) != 0) return -1;
    ctx->scope_keys = NULL;
    if (v->acl.query || v->acl.query_on) cfg->acl_query_active = true;
  }
  for (view_config_t *v = cfg->views; v; v = v->next) {
    ctx->scope_keys = v->keys;
    for (zone_config_t *z = v->zones; z; z = z->next) {
      zone_ext_t *zx = z->ext;
      if (!zx) continue;
      char label[DNS_NAME_TEXT_SIZE + 16];
      snprintf(label, sizeof(label), "zone '%.255s'", z->domain);
      if (acl_set_resolve(ctx, cfg, &zx->acl, label) != 0) return -1;
      if (zx->acl.query || zx->acl.query_on) cfg->acl_query_active = true;
      if (zx->transfer_acl_match != ACL_MATCH_DEFAULT) {
        const aml_t *l = config_acl_for(cfg, z, v->name, AML_ACL_TRANSFER);
        if (l && l->has_neg_key) {
          aml_report(ctx, NULL, label, "transfer-acl-match any/all cannot be used with an allow-transfer that has a negated key");
          return -1;
        }
      }
      if (zx->update_acl_match != ACL_MATCH_DEFAULT) {
        const aml_t *l = config_acl_for(cfg, z, v->name, AML_ACL_UPDATE);
        if (l && l->has_neg_key) {
          aml_report(ctx, NULL, label, "update-acl-match any/all cannot be used with an allow-update that has a negated key");
          return -1;
        }
      }
    }
    ctx->scope_keys = NULL;
  }
  return 0;
}

static void logging_config_free(logging_config_t *lc) {
  log_channel_t *ch = lc->channels;
  while (ch) {
    log_channel_t *next_ch = ch->next;
    free(ch->name);
    free(ch->file_path);
    pthread_mutex_destroy(&ch->lock);
    free(ch);
    ch = next_ch;
  }
  for (int c = 0; c < LOGC_COUNT; c++)
    for (int i = 0; i < lc->cat[c].n; i++) free(lc->cat[c].name[i]);
  free(lc->queries_channel_name);
  free(lc->responses_channel_name);
  memset(lc, 0, sizeof(*lc));
}

void free_server_config_fields(server_config_t *cfg) {
  if (!cfg) return;
  for (int j = 0; j < cfg->bind_address_count; j++)
    free(cfg->bind_addresses[j]);
  free(cfg->bind_addresses);
  cfg->bind_addresses = NULL;
  cfg->bind_address_count = 0;
  for (int j = 0; j < cfg->listen_stmt_count; j++)
    aml_unref(cfg->listen_stmts[j].list);
  free(cfg->listen_stmts);
  cfg->listen_stmts = NULL;
  cfg->listen_stmt_count = 0;
  free(cfg->listen);
  cfg->listen = NULL;
  cfg->listen_count = 0;
  aml_unref(cfg->blackhole);
  cfg->blackhole = NULL;

  if (cfg->user) { free(cfg->user); cfg->user = NULL; }
  if (cfg->group) { free(cfg->group); cfg->group = NULL; }
  if (cfg->pid_file) { free(cfg->pid_file); cfg->pid_file = NULL; }
  free(cfg->directory);
  cfg->directory = NULL;
  if (cfg->nsid_string) { free(cfg->nsid_string); cfg->nsid_string = NULL; }
  for (int j = 0; j < cfg->alias_resolvers_count; j++) free(cfg->alias_resolvers[j].ip);
  free(cfg->alias_resolvers);
  cfg->alias_resolvers = NULL;
  cfg->alias_resolvers_count = 0;
  notify_targets_free(cfg->also_notify, cfg->also_notify_count);
  cfg->also_notify = NULL;
  cfg->also_notify_count = 0;
  xo_free_fields(&cfg->xo);
  free(cfg->xfr_sources);
  cfg->xfr_sources = NULL;
  cfg->xfr_source_count = 0;
  remote_lists_free(cfg->remote_lists);
  cfg->remote_lists = NULL;
  OPENSSL_cleanse(cfg->cookie_secrets, sizeof(cfg->cookie_secrets));
  cfg->cookie_secret_count = 0;
  zone_cfg_index_free(&cfg->top_zone_index);

  /* パース中のトップレベル zone (パース済みの設定では既定の view に移っていて NULL) */
  {
    zone_config_t *curr = cfg->zones;
    while (curr) {
      zone_config_t *next = curr->next;
      free_zone_config(curr);
      curr = next;
    }
    cfg->zones = NULL;
  }

  view_config_t *v = cfg->views;
  while (v) {
    view_config_t *next_v = v->next;
    zone_cfg_index_free(&v->zone_index);
    free_view_db_fields(v);
    catz_names_free(v->catz_names, v->catz_count);
    if (v->name) free(v->name);
    acl_set_free(&v->acl);
    xo_free_fields(&v->xo);
    tsig_keys_free(v->keys);
    server_stmts_free(v->servers);
    notify_targets_free(v->also_notify, v->also_notify_count);
    for (int i = 0; i < v->match_clients_count; i++) free(v->match_clients[i]);
    if (v->match_clients) free(v->match_clients);
    if (v->match_clients_parsed) free(v->match_clients_parsed);
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

  catz_names_free(cfg->catz_names, cfg->catz_count);
  cfg->catz_names = NULL;
  cfg->catz_count = 0;
  tsig_keys_free(cfg->keys);
  cfg->keys = NULL;
  server_stmts_free(cfg->servers);
  cfg->servers = NULL;

  acl_def_t *a = cfg->acls;
  while (a) {
    acl_def_t *next_a = a->next;
    for (int i = 0; i < a->count; i++) free(a->entries[i]);
    free(a->entries);
    aml_unref(a->aml);
    free(a->name);
    free(a);
    a = next_a;
  }
  cfg->acls = NULL;
  acl_set_free(&cfg->acl);
  cfg->acl_query_active = false;

  if (cfg->control.socket_path) { free(cfg->control.socket_path); cfg->control.socket_path = NULL; }
  if (cfg->control.algorithm) { free(cfg->control.algorithm); cfg->control.algorithm = NULL; }
  if (cfg->control.secret) { free(cfg->control.secret); cfg->control.secret = NULL; }
  memset(&cfg->control, 0, sizeof(control_channel_config_t));
  if (cfg->dnstap.socket_path) { free(cfg->dnstap.socket_path); cfg->dnstap.socket_path = NULL; }
  if (cfg->dnstap.identity) { free(cfg->dnstap.identity); cfg->dnstap.identity = NULL; }
  if (cfg->dnstap.version) { free(cfg->dnstap.version); cfg->dnstap.version = NULL; }
  memset(&cfg->dnstap, 0, sizeof(dnstap_config_t));
  free_database_config(&cfg->database);
  free_rate_limit_config(&cfg->rrl);
  memset(&cfg->rrl, 0, sizeof(rate_limit_config_t));

  logging_config_free(&cfg->logging);
  for (int j = 0; j < cfg->controls_count; j++) {
    aml_unref(cfg->controls[j].allow);
    for (int k = 0; k < cfg->controls[j].nkeys; k++) {
      free(cfg->controls[j].keys[k]);
      free(cfg->controls[j].key_loc[k]);
    }
    free(cfg->controls[j].keys);
    free(cfg->controls[j].key_loc);
  }
  free(cfg->controls);
  cfg->controls = NULL;
  cfg->controls_count = 0;
  if (cfg->ecs_trusted_resolvers) {
    for (int i = 0; i < cfg->ecs_trusted_resolvers_count; i++) {
      free(cfg->ecs_trusted_resolvers[i]);
    }
    free(cfg->ecs_trusted_resolvers);
    cfg->ecs_trusted_resolvers = NULL;
    cfg->ecs_trusted_resolvers_count = 0;
  }
  if (cfg->ecs_trusted_resolvers_parsed) {
    free(cfg->ecs_trusted_resolvers_parsed);
    cfg->ecs_trusted_resolvers_parsed = NULL;
  }
  if (cfg->ecs_tags) {
    for (int i = 0; i < cfg->ecs_tag_count; i++) {
      free(cfg->ecs_tags[i].tag);
      for (int j = 0; j < cfg->ecs_tags[i].cidr_count; j++) {
        free(cfg->ecs_tags[i].cidrs[j].cidr);
      }
      free(cfg->ecs_tags[i].cidrs);
    }
    free(cfg->ecs_tags);
    cfg->ecs_tags = NULL;
    cfg->ecs_tag_count = 0;
  }
  if (cfg->location_tags) {
    for (int i = 0; i < cfg->location_tag_count; i++) {
      free(cfg->location_tags[i].tag);
      for (int j = 0; j < cfg->location_tags[i].cidr_count; j++) {
        free(cfg->location_tags[i].cidrs[j].cidr);
      }
      free(cfg->location_tags[i].cidrs);
    }
    free(cfg->location_tags);
    cfg->location_tags = NULL;
    cfg->location_tag_count = 0;
  }
}

char *read_entire_file(const char *path, dev_t *out_dev, ino_t *out_ino) {
  struct stat st;
  char *str = read_entire_file_stat(path, &st);
  if (str) {
    if (out_dev) *out_dev = st.st_dev;
    if (out_ino) *out_ino = st.st_ino;
  }
  return str;
}

/* 読んだ fd の fstat() の結果を out_st に返す (取れなければ 0 で埋める)。ゾーンの再読み込みは
 * サンドボックスの中なので、mtime もパスではなくこの fd から取る (X-13)。 */
char *read_entire_file_stat(const char *path, struct stat *out_st) {
  memset(out_st, 0, sizeof(*out_st));
  int fd = open_via_dir_cache(path, O_RDONLY, 0, false);
  if (fd < 0)
    return NULL;
  if (fstat(fd, out_st) != 0) memset(out_st, 0, sizeof(*out_st));

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

/* D-02: 真偽値は全ての文で同じ規則にする。BIND と同じく yes/no/true/false/1/0 を
 * 大文字小文字を区別せずに受け付け、それ以外は false を返す (呼び出し側で設定エラーにする)。 */
bool parse_config_bool(const char *s, bool *out) {
  if (!s || !out) return false;
  if (strcasecmp(s, "yes") == 0 || strcasecmp(s, "true") == 0 || strcmp(s, "1") == 0) {
    *out = true;
    return true;
  }
  if (strcasecmp(s, "no") == 0 || strcasecmp(s, "false") == 0 || strcmp(s, "0") == 0) {
    *out = false;
    return true;
  }
  return false;
}

/* additional-from-auth: 真偽値に加えて in-domain (別名 in-zone) を受け付ける */
static bool parse_additional_from_auth(const char *s, additional_from_auth_t *out) {
  bool b;
  if (s && (strcasecmp(s, "in-domain") == 0 || strcasecmp(s, "in-zone") == 0)) {
    *out = ADDITIONAL_AUTH_IN_DOMAIN;
    return true;
  }
  if (!parse_config_bool(s, &b)) return false;
  *out = b ? ADDITIONAL_AUTH_YES : ADDITIONAL_AUTH_NO;
  return true;
}

/* 不正な値を報告して設定エラーにする。zone が NULL でなければゾーン名を付ける。 */
static void report_bad_value(token_ctx_t *ctx, const char *zone, const char *name, const char *val,
                             const char *expected) {
  if (zone) {
    syslog(LOG_ERR, "[Config] zone '%s': invalid %s value '%s' (expected %s)", zone, name, val ? val : "", expected);
    fprintf(stderr, "[ERROR] zone '%s': invalid %s value '%s' (expected %s)\n", zone, name, val ? val : "", expected);
  } else {
    syslog(LOG_ERR, "[Config] invalid %s value '%s' (expected %s)", name, val ? val : "", expected);
    fprintf(stderr, "[ERROR] invalid %s value '%s' (expected %s)\n", name, val ? val : "", expected);
  }
  if (ctx) ctx->error_occurred = true;
}

static void report_bad_bool(token_ctx_t *ctx, const char *zone, const char *name, const char *val) {
  report_bad_value(ctx, zone, name, val, "yes or no");
}

/* "<name> <bool>;" の値とセミコロンを読む。不正な値や構文は -1。 */
static int parse_bool_statement(token_ctx_t *ctx, const char *zone, const char *name, bool *out) {
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_STRING) { free_token(&tok); return -1; }
  if (!parse_config_bool(tok.value, out)) {
    report_bad_bool(ctx, zone, name, tok.value);
    free_token(&tok);
    return -1;
  }
  free_token(&tok);
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) { free_token(&tok); return -1; }
  free_token(&tok);
  return 0;
}

bool match_cidr(const char *client_ip_str, const char *cidr_str) {
  if (!client_ip_str || !cidr_str)
    return false;
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
  if (!list || !count) return -1;
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
    char *val = tok.value;
    tok.value = NULL;
    free_token(&tok);
    APPEND_STR(*list, *count, val);
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

typedef enum { ACL_KEY_AS_LIST_ENTRY, ACL_KEY_AS_TSIG_FIELD, ACL_KEY_REJECT, ACL_KEY_MARKED } acl_key_mode_t;

static int parse_acl_list(token_ctx_t *ctx, char ***list, int *count,
                           acl_key_mode_t key_mode, char ***tsig_keys_out, int *tsig_keys_count_out) {
    if (!list || !count) return -1;
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
            if (key_mode == ACL_KEY_REJECT) {
                /* match-clients はクライアントアドレスだけで評価する。key を受け付けると
                 * 何にもマッチしないエントリーが黙って残るので、設定エラーにする。 */
                syslog(LOG_ERR, "[Config] 'key' entries are not supported in match-clients (address match only)");
                fprintf(stderr, "[ERROR] 'key' entries are not supported in match-clients (address match only)\n");
                if (ctx) ctx->error_occurred = true;
                return -1;
            }
            tok = get_next_token(ctx);
            if (tok.type != TOKEN_STRING) { free_token(&tok); return -1; }
            char *val = tok.value;
            tok.value = NULL;
            free_token(&tok);
            if (key_mode == ACL_KEY_AS_TSIG_FIELD && tsig_keys_out && tsig_keys_count_out) {
                APPEND_STR(*tsig_keys_out, *tsig_keys_count_out, val);
            } else if (key_mode == ACL_KEY_MARKED) {
                /* 名前付き ACL の key 要素。参照先の文で意味が決まるので印を付けて残す */
                size_t vlen = strlen(val);
                char *marked = malloc(vlen + 2);
                if (!marked) {
                    free(val);
                    if (ctx) ctx->error_occurred = true;
                    return -1;
                }
                marked[0] = ACL_KEY_MARK;
                memcpy(marked + 1, val, vlen + 1);
                free(val);
                APPEND_STR(*list, *count, marked);
            } else {
                APPEND_STR(*list, *count, val);
            }
        } else if (strcmp(tok.value, "!") == 0) {
            free_token(&tok);
            tok = get_next_token(ctx);
            if (tok.type == TOKEN_LBRACE) {
                brace_depth++; in_negated_block = true; free_token(&tok); continue;
            }
            if (tok.type != TOKEN_STRING) { free_token(&tok); return -1; }
            if (in_negated_block) {
                if (strcmp(tok.value, "any") != 0) {
                    char *val = tok.value;
                    tok.value = NULL;
                    free_token(&tok);
                    APPEND_STR(*list, *count, val);
                } else {
                    free_token(&tok);
                }
            } else {
                char buf[256];
                snprintf(buf, sizeof(buf), "!%s", tok.value);
                free_token(&tok);
                char *dup_val = strdup(buf);
                if (!dup_val) {
                    if (ctx) ctx->error_occurred = true;
                    return -1;
                }
                APPEND_STR(*list, *count, dup_val);
            }
        } else {
            char *val = tok.value;
            tok.value = NULL;
            free_token(&tok);
            bool double_negated = false;
            if (in_negated_block && val[0] == '!') {
                char *unbanged = strdup(val + 1);
                free(val);
                if (!unbanged) {
                    if (ctx) ctx->error_occurred = true;
                    return -1;
                }
                val = unbanged;
                double_negated = true; // !{ !X; } => X
            }
            if (in_negated_block && strcmp(val, "any") == 0) {
                free(val);
            } else if (in_negated_block && !double_negated) {
                size_t buflen = strlen(val) + 2;
                char *negated = malloc(buflen);
                if (!negated) {
                    free(val);
                    if (ctx) ctx->error_occurred = true;
                    return -1;
                }
                snprintf(negated, buflen, "!%s", val);
                free(val);
                APPEND_STR(*list, *count, negated);
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



/* Where the lexer is: "file:line" (or "line N" for a configuration given as a string).  The line is counted from the text read so far
 * (the innermost file of the include stack), so it is the line of the token that was read last. */
static void ctx_location(const token_ctx_t *ctx, char *buf, size_t n) {
  int depth = ctx->depth >= 0 && ctx->depth < MAX_INCLUDE_DEPTH ? ctx->depth : 0;
  const config_file_frame_t *f = &ctx->stack[depth];
  int line = 1;
  if (f->src) {
    size_t end = f->pos < f->len ? f->pos : f->len;
    for (size_t i = 0; i < end; i++)
      if (f->src[i] == '\n') line++;
  }
  if (f->file_path)
    snprintf(buf, n, "%.200s:%d", f->file_path, line);
  else
    snprintf(buf, n, "line %d", line);
}

static const char *tok_desc(const conf_token_t *t, char *buf, size_t n) {
  switch (t->type) {
    case TOKEN_EOF: return "end of file";
    case TOKEN_LBRACE: return "'{'";
    case TOKEN_RBRACE: return "'}'";
    case TOKEN_SEMICOLON: return "';'";
    default: snprintf(buf, n, "'%.64s'", t->value ? t->value : ""); return buf;
  }
}

/* A syntax error in the statement `what`, reported with the place in the file (stderr and syslog) and made fatal.  The settings text of a
 * database zone is hostile input and is never echoed: restricted mode only records that the statement is wrong (restricted_err). */
static void conf_error(token_ctx_t *ctx, const char *what, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void conf_error(token_ctx_t *ctx, const char *what, const char *fmt, ...) {
  if (!ctx) return;
  if (ctx->restricted) {
    if (!ctx->restricted_err[0])
      snprintf(ctx->restricted_err, sizeof(ctx->restricted_err), "%s: syntax error or invalid value", what);
    ctx->error_occurred = true;
    return;
  }
  char loc[300], msg[400];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);
  ctx_location(ctx, loc, sizeof(loc));
  syslog(LOG_ERR, "[Config] %s: %s: %s", loc, what, msg);
  fprintf(stderr, "[ERROR] %s: %s: %s\n", loc, what, msg);
  ctx->error_occurred = true;
}

/* ---- BIND address match lists (BIND 9.20 ARM "Address Match Lists", dns_tsig_acl.h) ----
 *   address_match_list = address_match_element; ...
 *   address_match_element = [ ! ] ( <ip_address> | <ip_prefix> | key <key_id> | <acl_name> | { address_match_list } )
 * `any`, `none`, `localhost` and `localnets` are predefined acl names.  The statements that take a list read it into an aml_t (names are
 * resolved when the whole file has been read: an acl may be written after its first use), and allow-transfer / allow-update also
 * keep the flat string lists the older code (settings sent to secondaries, database zones) works with. */
#define AML_PARSE_DEPTH_MAX 8

static bool aml_text_is(const char *t, const char *name) {
  return strcasecmp(t, name) == 0;
}

/* `what`: for the messages.  The '{' has been read; reads up to and including the matching '}'.  NULL after reporting an error. */
static aml_t *parse_aml_body(token_ctx_t *ctx, const char *what, int depth) {
  aml_t *l = aml_new();
  char db[96];
  if (!l) {
    if (ctx) ctx->error_occurred = true;
    return NULL;
  }
  for (;;) {
    conf_token_t tok = get_next_token(ctx);
    if (tok.type == TOKEN_RBRACE) {
      free_token(&tok);
      return l;
    }
    aml_elem_t e;
    memset(&e, 0, sizeof(e));
    if (tok.type == TOKEN_STRING && tok.value && !tok.is_quoted && tok.value[0] == '!') {
      e.neg = true;
      if (tok.value[1] == '\0') {
        free_token(&tok);
        tok = get_next_token(ctx);
      } else {
        char *rest = strdup(tok.value + 1);
        free(tok.value);
        tok.value = rest;
        if (!rest) {
          if (ctx) ctx->error_occurred = true;
          aml_unref(l);
          return NULL;
        }
      }
    }
    char loc[300];
    ctx_location(ctx, loc, sizeof(loc));
    bool bad = false;
    if (tok.type == TOKEN_LBRACE) {
      free_token(&tok);
      if (depth + 1 >= AML_PARSE_DEPTH_MAX) {
        conf_error(ctx, what, "address match lists are nested more than %d deep", AML_PARSE_DEPTH_MAX);
        aml_unref(l);
        return NULL;
      }
      e.kind = AML_E_LIST;
      e.u.list = parse_aml_body(ctx, what, depth + 1);
      if (!e.u.list) {
        aml_unref(l);
        return NULL;
      }
    } else if (tok.type == TOKEN_STRING && tok.value && tok.value[0] != '\0') {
      if (!tok.is_quoted && strcmp(tok.value, "key") == 0) {
        free_token(&tok);
        tok = get_next_token(ctx);
        /* (the settings text of a database zone may carry an empty name: db_settings_parse() reports it with its own message) */
        if (tok.type != TOKEN_STRING || !tok.value || (tok.value[0] == '\0' && !ctx->restricted)) {
          conf_error(ctx, what, "expected a key name after 'key' but found %s", tok_desc(&tok, db, sizeof(db)));
          free_token(&tok);
          aml_unref(l);
          return NULL;
        }
        e.kind = AML_E_KEY;
      } else if (aml_text_is(tok.value, "any")) {
        e.kind = AML_E_ANY;
      } else if (aml_text_is(tok.value, "none")) {
        e.kind = AML_E_NONE;
      } else if (aml_text_is(tok.value, "localhost")) {
        e.kind = AML_E_LOCALHOST;
      } else if (aml_text_is(tok.value, "localnets")) {
        e.kind = AML_E_LOCALNETS;
      } else if (cidr_entry_parse(&e.u.net, tok.value)) {
        e.kind = AML_E_NET;
      } else {
        e.kind = AML_E_NAME;
      }
      if (e.kind == AML_E_ANY || e.kind == AML_E_NONE || e.kind == AML_E_LOCALHOST || e.kind == AML_E_LOCALNETS) {
        for (char *p = tok.value; *p; p++) *p = (char)tolower((unsigned char)*p);
      }
      e.text = tok.value;
      tok.value = NULL;
      free_token(&tok);
      if (e.kind == AML_E_KEY || e.kind == AML_E_NAME) {
        e.loc = strdup(loc);
        if (!e.loc) bad = true;
      }
    } else {
      conf_error(ctx, what, "expected an address, prefix, 'key <name>', an acl name or '{' but found %s", tok_desc(&tok, db, sizeof(db)));
      free_token(&tok);
      aml_unref(l);
      return NULL;
    }
    if (!bad) {
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_SEMICOLON) {
        conf_error(ctx, what, "expected ';' after the element but found %s", tok_desc(&tok, db, sizeof(db)));
        free_token(&tok);
        bad = true;
      } else {
        free_token(&tok);
      }
    }
    if (bad || !aml_push(l, &e)) {
      if (!bad && ctx) ctx->error_occurred = true;
      free(e.text);
      free(e.loc);
      if (e.kind == AML_E_LIST) aml_unref(e.u.list);
      aml_unref(l);
      if (ctx) ctx->error_occurred = true;
      return NULL;
    }
  }
}

/* `{ list };`  (a BIND 9.20 allow-transfer may also carry `port <n>` and `transport <name>` in front of the braces: they restrict the
 * transfer to a port or a transport, which this server has no way to honour; refusing the statement is safer than ignoring them) */
static aml_t *parse_aml_statement(token_ctx_t *ctx, const char *what) {
  char db[96];
  conf_token_t tok = get_next_token(ctx);
  if (tok.type == TOKEN_STRING && tok.value && (strcmp(tok.value, "port") == 0 || strcmp(tok.value, "transport") == 0)) {
    conf_error(ctx, what, "'%s' in front of the address list is not supported", tok.value);
    free_token(&tok);
    return NULL;
  }
  if (tok.type != TOKEN_LBRACE) {
    conf_error(ctx, what, "expected '{' but found %s", tok_desc(&tok, db, sizeof(db)));
    free_token(&tok);
    return NULL;
  }
  free_token(&tok);
  aml_t *l = parse_aml_body(ctx, what, 0);
  if (!l) return NULL;
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) {
    conf_error(ctx, what, "expected ';' after '}' but found %s", tok_desc(&tok, db, sizeof(db)));
    free_token(&tok);
    aml_unref(l);
    return NULL;
  }
  free_token(&tok);
  return l;
}

/* ---- listen-on, listen-on-v6, bind-address and blackhole (BIND 9.20 ARM "Interfaces", "blackhole") ----
 *   listen-on [ port <integer> ] [ proxy <string> ] [ tls <string> ] [ http <string> ] { <address_match_element>; ... };   (may be repeated)
 *   blackhole { <address_match_element>; ... };
 * The addresses to listen on are computed once, when the parse ends (config_build_listen()); the Frontend and the Backend open their
 * sockets from server_config_t.listen only and never look at these statements again.  A reload that changes them is "restart needed". */
#define LISTEN_STMT_MAX 256

static int g_port_override;
void config_set_port_override(int port) {
  g_port_override = (port > 0 && port <= 65535) ? port : 0;
}

static void conf_warn_loc(const char *loc, const char *what, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void conf_warn_loc(const char *loc, const char *what, const char *fmt, ...) {
  char msg[300];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);
  syslog(LOG_WARNING, "[Config] %s: %s: %s", loc, what, msg);
  fprintf(stderr, "[WARNING] %s: %s: %s\n", loc, what, msg);
}

/* bind-address elements must be IPv4 or IPv6 addresses: a typo used to bind nothing, silently (bind_address_loc says where they were read). */
static int bind_address_check(token_ctx_t *ctx, server_config_t *cfg, int first_new) {
  ctx_location(ctx, cfg->bind_address_loc, sizeof(cfg->bind_address_loc));
  for (int i = first_new; i < cfg->bind_address_count; i++) {
    uint8_t b[16];
    const char *a = cfg->bind_addresses[i];
    if (!a || (inet_pton(AF_INET, a, b) != 1 && inet_pton(AF_INET6, a, b) != 1)) {
      conf_error(ctx, "options", "bind-address: '%.64s' is not an IPv4 or IPv6 address", a ? a : "");
      return -1;
    }
  }
  return 0;
}

/* "file:line" of the token read last, as the `loc` of conf_warn_loc() */
static void conf_warn_here(const token_ctx_t *ctx, const char *what, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void conf_warn_here(const token_ctx_t *ctx, const char *what, const char *fmt, ...) {
  char loc[300], msg[300];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);
  ctx_location(ctx, loc, sizeof(loc));
  conf_warn_loc(loc, what, "%s", msg);
}

/* tcp-initial-timeout, tcp-idle-timeout, tcp-keepalive-timeout, tcp-advertised-timeout (BIND 9.20 lib/isccfg/namedconf.c: cfg_type_uint32;
 * bin/named/server.c: the value * 100 is milliseconds, MIN_/MAX_*_TIMEOUT).  BIND's unit is 100 ms and a value outside [min, max] is
 * raised / lowered with a warning (the same messages).  KariDNS's own earlier unit was the millisecond, so a number written with the suffix
 * `ms` (`10000ms`) is still taken as milliseconds, unchanged (no clamping: the operator wrote the exact value).  The decision for the two
 * options that existed before (2026-10-29, plan A): a bare number above BIND's maximum of 1200 (120 s) is almost certainly an old value
 * in milliseconds, which BIND would lower to 120 s without a word of explanation; here it is an error that names the `ms` suffix.
 * Reads the value and the semicolon.  *out_ms is the timeout in milliseconds. */
static int parse_tcp_timeout(token_ctx_t *ctx, const char *key, uint32_t min_units, uint32_t max_units, bool over_is_error,
                             uint32_t *out_ms) {
  char what[48];
  snprintf(what, sizeof(what), "options %s", key);
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_STRING || !tok.value) { free_token(&tok); return -1; }
  const char *s = tok.value;
  size_t nd = 0;
  while (s[nd] >= '0' && s[nd] <= '9') nd++;
  bool ms = (s[nd] != '\0' && strcasecmp(s + nd, "ms") == 0);
  uint64_t v = 0;
  if (nd == 0 || nd > 10 || (s[nd] != '\0' && !ms) || (v = strtoull(s, NULL, 10)) > UINT32_MAX) {
    conf_error(ctx, what, "invalid value '%.64s' (expected a non-negative integer in units of 100 ms, or a number of milliseconds followed by \"ms\")", s);
    free_token(&tok);
    return -1;
  }
  uint32_t res;
  if (ms) {
    res = (uint32_t)v;
  } else {
    if (v > max_units) {
      if (over_is_error) {
        conf_error(ctx, what, "%llu is more than the maximum of %u (%u seconds): a number without a unit is in units of 100 ms, as in BIND; "
                   "if %llu milliseconds were meant, write %llums", (unsigned long long)v, max_units, max_units / 10,
                   (unsigned long long)v, (unsigned long long)v);
        free_token(&tok);
        return -1;
      }
      conf_warn_here(ctx, what, "value is out of range: lowering to %u", max_units);
      v = max_units;
    } else if (v < min_units) {
      conf_warn_here(ctx, what, "value is out of range: raising to %u", min_units);
      v = min_units;
    }
    res = (uint32_t)(v * 100);
  }
  free_token(&tok);
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) { free_token(&tok); return -1; }
  free_token(&tok);
  *out_ms = res;
  return 0;
}

/* minimal-responses (BIND 9.20 lib/isccfg/namedconf.c: `( no-auth | no-auth-recursive | <boolean> )`, bin/named/server.c: the value of the
 * boolean decides yes / no, the words select dns_minimal_noauth / dns_minimal_noauthrec).  Reads the value and the semicolon. */
static int parse_minimal_responses(token_ctx_t *ctx, const char *what, uint8_t *out) {
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_STRING || !tok.value) { free_token(&tok); return -1; }
  bool b;
  if (strcasecmp(tok.value, "no-auth") == 0) {
    *out = MINIMAL_NO_AUTH;
  } else if (strcasecmp(tok.value, "no-auth-recursive") == 0) {
    *out = MINIMAL_NO_AUTH_RECURSIVE;
  } else if (parse_config_bool(tok.value, &b)) {
    *out = b ? MINIMAL_YES : MINIMAL_NO;
  } else {
    conf_error(ctx, what, "minimal-responses: invalid value '%.64s' (expected yes, no, no-auth or no-auth-recursive)", tok.value);
    free_token(&tok);
    return -1;
  }
  free_token(&tok);
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) { free_token(&tok); return -1; }
  free_token(&tok);
  return 0;
}

/* version, hostname (`( <quoted_string> | none )`: a quoted "none" is the text none) and server-id (`( <quoted_string> | none | hostname )`);
 * the key has been read.  The texts are cut at 255 octets, one TXT character-string (BIND puttxt()). */
static int parse_chaos_statement(token_ctx_t *ctx, server_config_t *cfg, const char *key) {
  char what[32];
  snprintf(what, sizeof(what), "options %s", key);
  chaos_cfg_t *c = &cfg->chaos;
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_STRING || !tok.value) { free_token(&tok); return -1; }
  bool is_sid = strcmp(key, "server-id") == 0;
  bool none = !tok.is_quoted && strcasecmp(tok.value, "none") == 0;
  bool host = is_sid && !tok.is_quoted && strcasecmp(tok.value, "hostname") == 0;
  char *text = is_sid ? c->server_id : key[0] == 'v' ? c->version : c->hostname;
  text[0] = '\0';
  if (!none && !host) {
    size_t n = strlen(tok.value);
    if (n > CHAOS_TXT_MAX) {
      conf_warn_here(ctx, what, "the text is longer than %d octets: it is cut (a TXT character-string holds at most %d)", CHAOS_TXT_MAX, CHAOS_TXT_MAX);
      n = CHAOS_TXT_MAX;
    }
    memcpy(text, tok.value, n);
    text[n] = '\0';
  }
  if (is_sid) {
    c->server_id_set = true;
    c->server_id_none = none;
    c->server_id_hostname = host;
  } else if (key[0] == 'v') {
    c->version_set = true;
    c->version_none = none;
  } else {
    c->hostname_set = true;
    c->hostname_none = none;
  }
  free_token(&tok);
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) { free_token(&tok); return -1; }
  free_token(&tok);
  return 0;
}

/* When the parse ends: the texts version.bind, hostname.bind and id.server serve (bin/named/builtin.c version_lookup(), hostname_lookup(),
 * id_lookup(): not written = the product version, the host name, nothing; `none` = no TXT record).  server-id is also the NSID of the
 * responses (lib/ns/client.c: server_id, else the host name when server-id is `hostname`), so a different `nsid` is a mistake. */
static int chaos_finish(token_ctx_t *ctx, server_config_t *cfg) {
  chaos_cfg_t *c = &cfg->chaos;
  char hn[256];
  bool have_hn = gethostname(hn, sizeof(hn)) == 0;
  hn[sizeof(hn) - 1] = '\0';
  c->has_version = !(c->version_set && c->version_none);
  snprintf(c->r_version, sizeof(c->r_version), "%s", c->version_set ? c->version : KARIDNS_VERSION);
  c->has_hostname = !(c->hostname_set && c->hostname_none) && (c->hostname_set || have_hn);
  snprintf(c->r_hostname, sizeof(c->r_hostname), "%s", c->hostname_set ? c->hostname : hn);
  c->has_id = c->server_id_set && !c->server_id_none && (!c->server_id_hostname || have_hn);
  snprintf(c->r_id, sizeof(c->r_id), "%s", c->server_id_hostname ? hn : c->server_id);
  if (c->has_id) {
    if (cfg->nsid_string && strcmp(cfg->nsid_string, c->r_id) != 0) {
      conf_error(ctx, "options server-id", "server-id '%.64s' is also the NSID of the responses, but nsid says '%.64s'; write one of them, or the same text in both",
                 c->r_id, cfg->nsid_string);
      return -1;
    }
    if (!cfg->nsid_string && (cfg->nsid_string = strdup(c->r_id)) == NULL) return -1;
  }
  if (cfg->dnstap.enabled && cfg->dnstap.bind_form && !cfg->dnstap.socket_path) {   /* BIND check_dnstap(): 'dnstap-output' must be set if 'dnstap' is set */
    conf_error(ctx, "dnstap", "'dnstap-output' must be set if 'dnstap' is set (dnstap-output unix \"/path/to/socket\";)");
    return -1;
  }
  for (const view_config_t *v = cfg->views; v; v = v->next) {
    if (v->max_udp_size) cfg->any_view_max_udp = true;
    if (v->require_cookie_set) cfg->any_view_cookie = true;
  }
  return 0;
}

/* `listen-on [port n] [proxy x] [tls x] [http x] { list };`  The key has been read.  BIND 9.20 (lib/isccfg/namedconf.c, listenon_tuple_fields)
 * takes the four keywords in any order; `port` is an integer.  proxy (PROXYv2), tls (DoT) and http (DoH) need listeners this server does not
 * have: refusing the statement is safer than listening in plain DNS where the operator asked for an encrypted or proxied listener. */
static int parse_listen_statement(token_ctx_t *ctx, server_config_t *cfg, bool v6) {
  const char *what = v6 ? "options listen-on-v6" : "options listen-on";
  char db[96];
  char loc[300];
  ctx_location(ctx, loc, sizeof(loc));
  int port = 0;
  conf_token_t tok;
  for (;;) {
    tok = get_next_token(ctx);
    if (tok.type == TOKEN_LBRACE) {
      free_token(&tok);
      break;
    }
    if (tok.type != TOKEN_STRING || !tok.value || tok.is_quoted) {
      conf_error(ctx, what, "expected 'port' or '{' but found %s", tok_desc(&tok, db, sizeof(db)));
      free_token(&tok);
      return -1;
    }
    if (strcmp(tok.value, "port") == 0) {
      free_token(&tok);
      if (port) {
        conf_error(ctx, what, "'port' is given twice");
        return -1;
      }
      tok = get_next_token(ctx);
      char *end = NULL;
      long p = (tok.type == TOKEN_STRING && tok.value && tok.value[0]) ? strtol(tok.value, &end, 10) : 0;
      if (tok.type != TOKEN_STRING || !tok.value || !end || *end != '\0' || p < 1 || p > 65535) {
        conf_error(ctx, what, "port: invalid port '%.64s' (expected 1-65535)", tok.type == TOKEN_STRING && tok.value ? tok.value : "");
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      port = (int)p;
    } else if (strcmp(tok.value, "tls") == 0 || strcmp(tok.value, "http") == 0 || strcmp(tok.value, "proxy") == 0) {
      conf_error(ctx, what, "'%s' is not supported: this server has no DNS-over-TLS, DNS-over-HTTPS or PROXYv2 listener", tok.value);
      free_token(&tok);
      return -1;
    } else {
      conf_error(ctx, what, "expected 'port' or '{' but found '%.64s'", tok.value);
      free_token(&tok);
      return -1;
    }
  }
  aml_t *l = parse_aml_body(ctx, what, 0);
  if (!l) return -1;
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) {
    conf_error(ctx, what, "expected ';' after '}' but found %s", tok_desc(&tok, db, sizeof(db)));
    free_token(&tok);
    aml_unref(l);
    return -1;
  }
  free_token(&tok);
  if (cfg->listen_stmt_count >= LISTEN_STMT_MAX) {
    conf_error(ctx, what, "more than %d listen-on / listen-on-v6 statements", LISTEN_STMT_MAX);
    aml_unref(l);
    return -1;
  }
  listen_stmt_t *ns = realloc(cfg->listen_stmts, (size_t)(cfg->listen_stmt_count + 1) * sizeof(*ns));
  if (!ns) {
    ctx->error_occurred = true;
    aml_unref(l);
    return -1;
  }
  cfg->listen_stmts = ns;
  listen_stmt_t *s = &ns[cfg->listen_stmt_count++];
  memset(s, 0, sizeof(*s));
  s->v6 = v6;
  s->port = port;
  s->list = l;
  snprintf(s->loc, sizeof(s->loc), "%s", loc);
  return 0;
}

/* The lists of listen-on and blackhole are resolved like the others; none may name a TSIG key (nothing is signed at that point). */
static int listen_lists_resolve(token_ctx_t *ctx, server_config_t *cfg) {
  for (int i = 0; i < cfg->listen_stmt_count; i++) {
    listen_stmt_t *s = &cfg->listen_stmts[i];
    const char *what = s->v6 ? "options listen-on-v6" : "options listen-on";
    if (aml_resolve(ctx, cfg, s->list, what, false, 0) != 0) return -1;
    if (s->list->has_key) {
      aml_report(ctx, s->loc, what, "'key' elements cannot be used in an address list that selects interfaces");
      return -1;
    }
  }
  if (cfg->blackhole) {
    if (aml_resolve(ctx, cfg, cfg->blackhole, "options blackhole", false, 0) != 0) return -1;
    if (cfg->blackhole->has_key) {
      aml_report(ctx, NULL, "options blackhole", "'key' elements cannot be used here (a request is dropped before it is read)");
      return -1;
    }
  }
  return 0;
}

/* `listen-on { any; }`: BIND (lib/ns/interfacemgr.c, listenon_is_ip6_any()) binds one wildcard socket only when the whole list is a plain
 * `any`; any other list is matched against each interface address.  A named acl that holds just `any` counts (dns_acl_isany()). */
static bool aml_is_plain_any(const aml_t *l, int depth) {
  if (!l || depth > AML_MAX_DEPTH || l->count != 1) return false;
  const aml_elem_t *e = &l->elems[0];
  if (e->neg) return false;
  if (e->kind == AML_E_ANY) return true;
  return e->kind == AML_E_LIST && aml_is_plain_any(e->u.list, depth + 1);
}

typedef struct {
  listen_addr_t a;
  const char *loc;   /* where it came from (a listen-on statement, bind-address, the default) */
} listen_cand_t;

static const char *const k_listen_default_loc = "the default";

/* Adds one address.  The same address and port again is the same socket (the union of two statements); the same address with another port
 * is an error (decided for this server: one address, one port).  0, or -1 after reporting. */
static int listen_cand_add(token_ctx_t *ctx, listen_cand_t *v, int *n, uint8_t family, const uint8_t *addr, int port, const char *loc,
                           const char *what) {
  size_t alen = family == AF_INET ? 4 : 16;
  for (int i = 0; i < *n; i++) {
    if (v[i].a.family != family || memcmp(v[i].a.addr, addr, alen) != 0) continue;
    if (v[i].a.port == port) return 0;
    aml_report(ctx, loc, what, "address %s is listened on at port %d (%s) and at port %d: one address can have only one port", v[i].a.text,
               (int)v[i].a.port, v[i].loc, port);
    return -1;
  }
  if (*n >= KARIDNS_LISTEN_MAX) {
    aml_report(ctx, loc, what, "more than %d addresses to listen on (the limit of this server); list fewer addresses or use 'any'", KARIDNS_LISTEN_MAX);
    return -1;
  }
  listen_cand_t *c = &v[(*n)++];
  memset(c, 0, sizeof(*c));
  c->a.family = family;
  memcpy(c->a.addr, addr, alen);
  c->a.port = (uint16_t)port;
  c->a.wildcard = true;
  for (size_t k = 0; k < alen; k++)
    if (addr[k]) c->a.wildcard = false;
  inet_ntop(family, addr, c->a.text, sizeof(c->a.text));
  c->loc = loc;
  return 0;
}

/* A literal address in the list that cannot be listened on is the operator's mistake worth a line: an IPv6 address in listen-on is
 * ignored by BIND ("IPv6 addresses are ignored, with a logged warning", ARM), and BIND listens on an address only when an interface
 * has it (do_scan() matches the list against the interface addresses). */
static void listen_warn_elements(const listen_stmt_t *s, const aml_iface_t *ifs, size_t nif) {
  const char *what = s->v6 ? "options listen-on-v6" : "options listen-on";
  int fam = s->v6 ? AF_INET6 : AF_INET;
  for (int i = 0; i < s->list->count; i++) {
    const aml_elem_t *e = &s->list->elems[i];
    if (e->kind != AML_E_NET || e->neg) continue;
    if (e->u.net.family != fam) {
      conf_warn_loc(s->loc, what, "'%.64s' is %s: it is ignored", e->text, s->v6 ? "an IPv4 address in listen-on-v6" : "an IPv6 address in listen-on");
      continue;
    }
    bool seen = false;
    for (size_t k = 0; k < nif && !seen; k++)
      if (ifs[k].family == fam && cidr_entry_match(&e->u.net, fam, ifs[k].addr)) seen = true;
    if (!seen)
      conf_warn_loc(s->loc, what, "'%.64s' matches no address of an interface of this host: nothing is listened on for it", e->text);
  }
}

/* Computes server_config_t.listen (BIND 9.20 ARM "listen-on", lib/ns/interfacemgr.c do_scan()):
 *  - a listen-on / listen-on-v6 statement selects the IPv4 / IPv6 interface addresses (of the snapshot aml_init_interfaces() took at start-up)
 *    that its list allows, at its own port or else options { port }; a plain `any` selects the wildcard address instead (BIND does that for
 *    IPv6; for IPv4 it binds each interface address, which would leave the addresses added later unserved, so the wildcard is used here too);
 *  - bind-address (this server's own statement) adds its addresses at options { port };
 *  - the result is the union, a duplicate collapses, one address with two ports is an error, and a specific address that a wildcard of the
 *    same family and port already covers is dropped (binding both would need SO_REUSEADDR games for nothing);
 *  - a family that nothing mentions listens on its wildcard address when some listen-on / listen-on-v6 statement exists (BIND's default of
 *    listen-on-v6 is "all IPv6 interfaces"); with only bind-address the list is exactly bind-address (as before); with neither, 0.0.0.0 and ::.
 * -p (config_set_port_override) replaces every port.  IPv6 link-local addresses of the interfaces are not selected: the snapshot has no scope. */
static int config_build_listen(token_ctx_t *ctx, server_config_t *cfg) {
  listen_cand_t v[KARIDNS_LISTEN_MAX];
  int n = 0;
  const aml_iface_t *ifs = NULL;
  size_t nif = aml_get_interfaces(&ifs);
  int defport = g_port_override ? g_port_override : (cfg->port > 0 ? cfg->port : 53);
  bool explicit_fam[2] = { false, false };   /* [0] IPv4, [1] IPv6 */
  static const uint8_t zero[16];

  for (int i = 0; i < cfg->listen_stmt_count; i++) {
    const listen_stmt_t *s = &cfg->listen_stmts[i];
    const char *what = s->v6 ? "options listen-on-v6" : "options listen-on";
    uint8_t fam = s->v6 ? AF_INET6 : AF_INET;
    int port = g_port_override ? g_port_override : (s->port ? s->port : defport);
    explicit_fam[s->v6 ? 1 : 0] = true;
    listen_warn_elements(s, ifs, nif);
    if (aml_is_plain_any(s->list, 0)) {
      if (listen_cand_add(ctx, v, &n, fam, zero, port, s->loc, what) != 0) return -1;
      continue;
    }
    for (size_t k = 0; k < nif; k++) {
      if (ifs[k].family != fam) continue;
      if (fam == AF_INET6 && ifs[k].addr[0] == 0xfe && (ifs[k].addr[1] & 0xc0) == 0x80) continue;   /* link-local: no scope in the snapshot */
      aml_subject_t subj = { .family = fam, .addr = ifs[k].addr, .key = NULL };
      if (!aml_allows(s->list, &subj)) continue;
      if (listen_cand_add(ctx, v, &n, fam, ifs[k].addr, port, s->loc, what) != 0) return -1;
    }
  }
  for (int i = 0; i < cfg->bind_address_count; i++) {
    uint8_t b[16];
    uint8_t fam;
    const char *bloc = cfg->bind_address_loc[0] ? cfg->bind_address_loc : "bind-address";
    if (inet_pton(AF_INET, cfg->bind_addresses[i], b) == 1) {
      fam = AF_INET;
    } else if (inet_pton(AF_INET6, cfg->bind_addresses[i], b) == 1) {
      fam = AF_INET6;
    } else {
      aml_report(ctx, bloc, "options bind-address", "'%.64s' is not an IPv4 or IPv6 address", cfg->bind_addresses[i]);
      return -1;
    }
    explicit_fam[fam == AF_INET6 ? 1 : 0] = true;
    if (listen_cand_add(ctx, v, &n, fam, b, defport, bloc, "options bind-address") != 0) return -1;
  }
  if (cfg->listen_stmt_count > 0 || cfg->bind_address_count == 0) {
    for (int f = 0; f < 2; f++)
      if (!explicit_fam[f] && listen_cand_add(ctx, v, &n, f ? AF_INET6 : AF_INET, zero, defport, k_listen_default_loc, "options listen-on") != 0)
        return -1;
  }
  /* a wildcard covers the specific addresses of its family and port */
  int m = 0;
  for (int i = 0; i < n; i++) {
    bool covered = false;
    if (!v[i].a.wildcard)
      for (int j = 0; j < n && !covered; j++)
        covered = v[j].a.wildcard && v[j].a.family == v[i].a.family && v[j].a.port == v[i].a.port;
    if (!covered) v[m++] = v[i];
  }
  n = m;
  free(cfg->listen);
  cfg->listen = NULL;
  cfg->listen_count = 0;
  if (n > 0) {
    cfg->listen = calloc((size_t)n, sizeof(listen_addr_t));
    if (!cfg->listen) {
      ctx->error_occurred = true;
      return -1;
    }
    for (int i = 0; i < n; i++) cfg->listen[i] = v[i].a;
    cfg->listen_count = n;
  } else {
    char loc[300];
    ctx_location(ctx, loc, sizeof(loc));
    conf_warn_loc(loc, "options", "listen-on, listen-on-v6 and bind-address select no address: the server would listen nowhere");
  }
  if (g_port_override) cfg->port = g_port_override;
  return 0;
}

/* The flat string list parse_acl_list() has always built from the same text: a nested { } list is spliced in (a negated one with every
 * element negated, a double negation positive, `any` dropped inside a negated list), and `key` elements go to keys_out (allow-transfer),
 * are listed by their name (allow-update) or carry ACL_KEY_MARK (acl blocks).  A negated key cannot be said that way: *inexact. */
static int aml_flatten(token_ctx_t *ctx, const aml_t *l, bool negate, acl_key_mode_t km, char ***list, int *count,
                       char ***keys_out, int *keys_count, bool *inexact, int depth) {
  if (depth > AML_PARSE_DEPTH_MAX) return -1;
  for (int i = 0; i < l->count; i++) {
    const aml_elem_t *e = &l->elems[i];
    bool neg = negate != e->neg;
    if (e->kind == AML_E_LIST) {
      if (aml_flatten(ctx, e->u.list, neg, km, list, count, keys_out, keys_count, inexact, depth + 1) != 0) return -1;
      continue;
    }
    if (e->kind == AML_E_KEY) {
      if (neg) {
        *inexact = true;
        continue;
      }
      if (km == ACL_KEY_AS_TSIG_FIELD && keys_out && keys_count) {
        APPEND_STR(*keys_out, *keys_count, strdup(e->text));
      } else if (km == ACL_KEY_MARKED) {
        size_t n = strlen(e->text);
        char *m = malloc(n + 2);
        if (!m) {
          if (ctx) ctx->error_occurred = true;
          return -1;
        }
        m[0] = ACL_KEY_MARK;
        memcpy(m + 1, e->text, n + 1);
        APPEND_STR(*list, *count, m);
      } else {
        APPEND_STR(*list, *count, strdup(e->text));
      }
      continue;
    }
    if (e->kind == AML_E_ANY && negate) continue;   /* `any` inside a negated list is dropped */
    size_t n = strlen(e->text);
    char *v = malloc(n + 2);
    if (!v) {
      if (ctx) ctx->error_occurred = true;
      return -1;
    }
    snprintf(v, n + 2, "%s%s", neg ? "!" : "", e->text);
    APPEND_STR(*list, *count, v);
  }
  return 0;
}

static bool aml_tree_has_key(const aml_t *l, int depth) {
  if (!l || depth > AML_PARSE_DEPTH_MAX) return false;
  for (int i = 0; i < l->count; i++) {
    if (l->elems[i].kind == AML_E_KEY) return true;
    if (l->elems[i].kind == AML_E_LIST && aml_tree_has_key(l->elems[i].u.list, depth + 1)) return true;
  }
  return false;
}

/* allow-query, allow-query-on, allow-notify at any level, and the lists of options / view: one statement into *slot.  A second
 * statement in the same block is an error, as in BIND. */
static int parse_aml_slot(token_ctx_t *ctx, const char *what, aml_t **slot) {
  if (*slot) {
    conf_error(ctx, what, "is written twice in the same block");
    return -1;
  }
  aml_t *l = parse_aml_statement(ctx, what);
  if (!l) return -1;
  *slot = l;
  return 0;
}

/* allow-transfer / allow-update of a zone: the BIND list and the flat lists.  A later statement replaces the earlier one. */
static int parse_zone_acl_stmt(token_ctx_t *ctx, zone_config_t *zone, zone_ext_t *x, bool transfer) {
  char what[DNS_NAME_TEXT_SIZE + 32];
  snprintf(what, sizeof(what), "zone '%.255s' %s", zone->domain ? zone->domain : "", transfer ? "allow-transfer" : "allow-update");
  aml_t *l = parse_aml_statement(ctx, what);
  if (!l) return -1;
  char ***list = transfer ? &x->allow_transfer : &x->allow_update;
  int *count = transfer ? &x->allow_transfer_count : &x->allow_update_count;
  acl_entry_t **parsed = transfer ? &x->allow_transfer_parsed : &x->allow_update_parsed;
  for (int i = 0; i < *count; i++) free((*list)[i]);
  free(*list);
  free(*parsed);
  *list = NULL;
  *parsed = NULL;
  *count = 0;
  if (transfer) {
    for (int i = 0; i < x->tsig_keys_count; i++) free(x->tsig_keys[i]);
    free(x->tsig_keys);
    x->tsig_keys = NULL;
    x->tsig_keys_count = 0;
  }
  bool inexact = false;
  if (aml_flatten(ctx, l, false, transfer ? ACL_KEY_AS_TSIG_FIELD : ACL_KEY_AS_LIST_ENTRY, list, count,
                  transfer ? &x->tsig_keys : NULL, transfer ? &x->tsig_keys_count : NULL, &inexact, 0) != 0) {
    aml_unref(l);
    return -1;
  }
  *parsed = acl_list_parse(*list, *count);
  /* a negated key cannot be written in the flat lists: the list has_neg_key once resolved and zone_settings_render() then writes
   * `none`; the settings text of a database zone has only the flat lists, so it is refused there */
  if (inexact && ctx->restricted) {
    conf_error(ctx, what, "a negated key is not allowed here");
    aml_unref(l);
    return -1;
  }
  aml_t **slot = transfer ? &x->acl.transfer : &x->acl.update;
  aml_unref(*slot);
  /* the settings text of a database zone is read without the rest of the configuration: it keeps the flat lists only */
  if (ctx->restricted) {
    aml_unref(l);
    *slot = NULL;
  } else {
    *slot = l;
  }
  return 0;
}

/* port <n>: 1..65535 */
static int read_port(token_ctx_t *ctx, const char *what, int *out) {
  char db[96];
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_STRING) {
    conf_error(ctx, what, "expected a port number after 'port' but found %s", tok_desc(&tok, db, sizeof(db)));
    free_token(&tok);
    return -1;
  }
  char *endptr;
  long pval = strtol(tok.value, &endptr, 10);
  if (tok.value[0] == '\0' || *endptr != '\0' || pval <= 0 || pval > 65535) {
    conf_error(ctx, what, "invalid port '%.64s' (expected 1-65535)", tok.value);
    free_token(&tok);
    return -1;
  }
  free_token(&tok);
  *out = (int)pval;
  return 0;
}

static bool is_ip_literal(const char *s) {
  struct in_addr a4;
  struct in6_addr a6;
  return inet_pton(AF_INET, s, &a4) == 1 || inet_pton(AF_INET6, s, &a6) == 1;
}

static void notify_targets_free(notify_target_t *l, int n) {
  for (int i = 0; l && i < n; i++) {
    free(l[i].ip);
    free(l[i].key);
    free(l[i].list);
    free(l[i].where);
    free(l[i].src_loc);
  }
  free(l);
}

static void remote_lists_free(remote_list_t *r) {
  while (r) {
    remote_list_t *next = r->next;
    notify_targets_free(r->items, r->count);
    free(r->name);
    free(r->where);
    free(r);
    r = next;
  }
}

/* `( <address> | * )` after the keyword kw (BIND 9.20 ARM: notify-source, transfer-source and their -v6 forms, the `source` / `source-v6` of a
 * primaries / also-notify list).  The 9.20 grammar has no port ("port configuration is deprecated" in the ARM; the grammar flags of
 * lib/isccfg/namedconf.c do not accept one): a following `port` is reported by the caller as the missing ';'.  family is the family of
 * the statement; allow_other accepts an address of the other family too (the KariDNS zone statement `notify-source` has always taken
 * either).  *state = 1 with addr, or 2 for `*`; *fam is the family found (AF_UNSPEC for `*`); *text (optional) gets a copy of the token.
 * -1 with a message that names the place. */
static int read_source_value(token_ctx_t *ctx, const char *what, const char *kw, int family, uint8_t *state, uint8_t addr[16],
                             bool allow_other, int *fam, char **text) {
  char db[96];
  uint8_t tmp[16] = {0};
  int other = family == AF_INET ? AF_INET6 : AF_INET;
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_STRING || !tok.value) {
    conf_error(ctx, what, "expected an %s address or '*' after '%s' but found %s", family == AF_INET ? "IPv4" : "IPv6", kw,
               tok_desc(&tok, db, sizeof(db)));
    free_token(&tok);
    return -1;
  }
  int rc = 0;
  if (strcmp(tok.value, "*") == 0) {
    *state = 2;
    memset(addr, 0, 16);
    *fam = AF_UNSPEC;
  } else if (inet_pton(family, tok.value, tmp) == 1) {
    *state = 1;
    memset(addr, 0, 16);
    memcpy(addr, tmp, family == AF_INET ? 4 : 16);
    *fam = family;
  } else if (allow_other && inet_pton(other, tok.value, tmp) == 1) {
    *state = 1;
    memset(addr, 0, 16);
    memcpy(addr, tmp, other == AF_INET ? 4 : 16);
    *fam = other;
  } else {
    bool wrong_family = inet_pton(other, tok.value, tmp) == 1;
    conf_error(ctx, what, "'%.64s' after '%s' is not an %s address or '*'%s", tok.value, kw, family == AF_INET ? "IPv4" : "IPv6",
               wrong_family ? (family == AF_INET ? " (an IPv6 address: use the -v6 form)" : " (an IPv4 address: use the form without -v6)") : "");
    rc = -1;
  }
  if (rc == 0 && text) {
    *text = strdup(tok.value);
    if (!*text) {
      ctx->error_occurred = true;
      rc = -1;
    }
  }
  free_token(&tok);
  return rc;
}

/* The element grammar of also-notify and of the top-level remote-servers / primaries / masters lists, from the BIND 9.20 ARM
 * ("also-notify", "remote-servers"):
 *   [ port <integer> ] [ source ( <ipv4> | * ) ] [ source-v6 ( <ipv6> | * ) ] { ( <list-name> | <ipv4> [ port <integer> ] | <ipv6> [ port <integer> ] ) [ key <string> ]; ... };
 * `port` before the braces is the port of the elements that have none (default 53).  A name is not looked up here: the lists may be
 * written after the statement, so the names are expanded when the whole configuration has been read (expand_targets()).  `tls` is in the
 * ARM grammar and is not supported: a clear error instead of a NOTIFY that goes somewhere else.  `source` / `source-v6` (no port in
 * 9.20) is the local address of the requests to the addresses written in this statement; `*` is the same as not written.
 * Appends to *list (the caller owns what was added also on failure); -1 with a message that names the place on a syntax error. */
static int parse_notify_targets(token_ctx_t *ctx, const char *what, notify_target_t **list, int *count, bool allow_cidr) {
  char db[96];
  int first = *count;
  int defport = 0;
  /* source / source-v6 of the statement (BIND 9.20 ARM): the address the requests to the addresses of this list leave from */
  uint8_t lsrc_state[2] = {0, 0};
  uint8_t lsrc[2][16];
  char lsrc_loc[300] = "";
  memset(lsrc, 0, sizeof(lsrc));
  conf_token_t tok = get_next_token(ctx);
  while (tok.type == TOKEN_STRING && tok.value) {
    if (strcmp(tok.value, "port") == 0) {
      free_token(&tok);
      if (defport) {
        conf_error(ctx, what, "'port' is given twice before '{'");
        return -1;
      }
      if (read_port(ctx, what, &defport) != 0) return -1;
    } else if (strcmp(tok.value, "source") == 0 || strcmp(tok.value, "source-v6") == 0) {
      int v6 = tok.value[6] != '\0';
      char kw[12];
      snprintf(kw, sizeof(kw), "%s", tok.value);
      free_token(&tok);
      if (ctx->restricted) {
        conf_error(ctx, what, "'%s' is not allowed here", kw);
        return -1;
      }
      if (lsrc_state[v6]) {
        conf_error(ctx, what, "'%s' is given twice before '{'", kw);
        return -1;
      }
      int fam = AF_UNSPEC;
      if (read_source_value(ctx, what, kw, v6 ? AF_INET6 : AF_INET, &lsrc_state[v6], lsrc[v6], false, &fam, NULL) != 0) return -1;
      ctx_location(ctx, lsrc_loc, sizeof(lsrc_loc));
    } else {
      break;
    }
    tok = get_next_token(ctx);
  }
  if (tok.type != TOKEN_LBRACE) {
    conf_error(ctx, what, "expected '{' but found %s", tok_desc(&tok, db, sizeof(db)));
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
    if (tok.type != TOKEN_STRING || !tok.value) {
      conf_error(ctx, what, "expected an address or a list name but found %s%s", tok_desc(&tok, db, sizeof(db)),
                 tok.type == TOKEN_EOF ? " (missing '}')" : "");
      free_token(&tok);
      return -1;
    }
    char loc[300];
    ctx_location(ctx, loc, sizeof(loc));
    char *name = tok.value;
    tok.value = NULL;
    free_token(&tok);
    notify_target_t *nl = safe_realloc_or_die(*list, sizeof(notify_target_t) * (size_t)(*count + 1));
    if (!nl) {
      free(name);
      ctx->error_occurred = true;
      return -1;
    }
    *list = nl;
    notify_target_t *e = &nl[*count];
    memset(e, 0, sizeof(*e));
    (*count)++;
    cidr_entry_t cidr_tmp;
    if (is_ip_literal(name) || (allow_cidr && strchr(name, '/') && cidr_entry_parse(&cidr_tmp, name)))
      e->ip = name;
    else
      e->list = name; /* a list name; in restricted mode (database zone) the caller refuses it */
    bool have_key = false;
    while (1) {
      tok = get_next_token(ctx);
      if (tok.type == TOKEN_SEMICOLON) {
        free_token(&tok);
        break;
      }
      if (tok.type != TOKEN_STRING || !tok.value) {
        conf_error(ctx, what, "expected ';' after '%.64s' but found %s", e->ip ? e->ip : e->list, tok_desc(&tok, db, sizeof(db)));
        free_token(&tok);
        return -1;
      }
      if (strcmp(tok.value, "port") == 0) {
        free_token(&tok);
        if (!e->ip) {
          conf_error(ctx, what, "'%.64s' is a list name, which takes no port (give the port to the list or to its addresses)", e->list);
          return -1;
        }
        if (e->port) {
          conf_error(ctx, what, "'%.64s' has two ports", e->ip);
          return -1;
        }
        if (read_port(ctx, what, &e->port) != 0) return -1;
      } else if (strcmp(tok.value, "key") == 0) {
        free_token(&tok);
        tok = get_next_token(ctx);
        if (tok.type != TOKEN_STRING || !tok.value || have_key) {
          if (have_key)
            conf_error(ctx, what, "'%.64s' has two keys", e->ip ? e->ip : e->list);
          else
            conf_error(ctx, what, "expected a key name after 'key' but found %s", tok_desc(&tok, db, sizeof(db)));
          free_token(&tok);
          return -1;
        }
        have_key = true;
        e->key = tok.value;
        tok.value = NULL;
        free_token(&tok);
      } else if (strcmp(tok.value, "tls") == 0) {
        conf_error(ctx, what, "'tls' is not supported (NOTIFY is sent over UDP, RFC 1996; remove 'tls')");
        free_token(&tok);
        return -1;
      } else {
        conf_error(ctx, what, "unexpected '%.64s' after '%.64s' (expected 'port', 'key' or ';')", tok.value,
                   e->ip ? e->ip : e->list);
        free_token(&tok);
        return -1;
      }
    }
    if (!ctx->restricted && (e->list || e->key)) e->where = strdup(loc);
  }
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) {
    conf_error(ctx, what, "expected ';' after '}' but found %s", tok_desc(&tok, db, sizeof(db)));
    free_token(&tok);
    return -1;
  }
  free_token(&tok);
  for (int i = first; i < *count; i++) {
    notify_target_t *e = &(*list)[i];
    /* An address without a port takes the `port` of its list; when the list has none either, the port stays 0 until expand_targets() knows
     * the lists this one is named in (BIND getipandkeylist(): an element of a nested list without a port takes the outer list's port),
     * and then 53.  A list name keeps the `port` of the statement it is written in for the same reason.  A database zone has no lists. */
    if (e->ip && e->port == 0) e->port = defport ? defport : (ctx->restricted ? 53 : 0);
    else if (e->list) e->port = defport;
    /* a list name keeps the sources of the list it names (expand_targets()); only the addresses written here get this statement's */
    if (e->ip) {
      for (int v = 0; v < 2; v++) {
        if (lsrc_state[v] != 1) continue; /* `*` is the same as not written */
        e->src_set[v] = 1;
        memcpy(e->src[v], lsrc[v], 16);
        if (!e->src_loc) e->src_loc = strdup(lsrc_loc);
      }
    }
  }
  return 0;
}

/* `what` { <address> [port <n>]; ... };  for the statements that list plain addresses (masters, forwarders, exempt-clients, ...):
 * appends to *list.  -1 with a message that names the place on a syntax error. */
static int parse_ip_port_list(token_ctx_t *ctx, const char *what, ip_port_t **list, int *count) {
  char db[96];
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_LBRACE) {
    conf_error(ctx, what, "expected '{' but found %s", tok_desc(&tok, db, sizeof(db)));
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
      conf_error(ctx, what, "expected an address but found %s%s", tok_desc(&tok, db, sizeof(db)),
                 tok.type == TOKEN_EOF ? " (missing '}')" : "");
      free_token(&tok);
      return -1;
    }
    char *ip_val = tok.value;
    tok.value = NULL;
    free_token(&tok);
    ip_port_t *_new_list = safe_realloc_or_die(*list, sizeof(ip_port_t) * (*count + 1));
    if (!_new_list) {
      free(ip_val);
      if (ctx) ctx->error_occurred = true;
      return -1;
    }
    *list = _new_list;
    (*list)[*count].ip = ip_val;
    (*list)[*count].port = 53;
    (*count)++;
    tok = get_next_token(ctx);
    if (tok.type == TOKEN_STRING && strcmp(tok.value, "port") == 0) {
      free_token(&tok);
      if (read_port(ctx, what, &(*list)[*count - 1].port) != 0) return -1;
      tok = get_next_token(ctx);
    }
    if (tok.type != TOKEN_SEMICOLON) {
      conf_error(ctx, what, "expected ';' after '%.64s' but found %s", ip_val, tok_desc(&tok, db, sizeof(db)));
      free_token(&tok);
      return -1;
    }
    free_token(&tok);
  }
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) {
    conf_error(ctx, what, "expected ';' after '}' but found %s", tok_desc(&tok, db, sizeof(db)));
    free_token(&tok);
    return -1;
  }
  free_token(&tok);
  return 0;
}

/* B9a: alias-resolver { <ip> [port <n>]; ... };  1..KARIDNS_ALIAS_RESOLVERS_MAX IP address literals (the Backend connects to addresses only,
 * never to a host name).  A later statement replaces an earlier one.  -1 with an error message on a bad entry. */
static int parse_alias_resolvers(token_ctx_t *ctx, const char *where, ip_port_t **list, int *count) {
  for (int i = 0; i < *count; i++) free((*list)[i].ip);
  free(*list);
  *list = NULL;
  *count = 0;
  if (parse_ip_port_list(ctx, "alias-resolver", list, count) != 0) return -1;
  const char *bad = NULL;
  if (*count > KARIDNS_ALIAS_RESOLVERS_MAX) {
    bad = "more than 8 entries";
  } else {
    for (int i = 0; i < *count && !bad; i++) {
      struct in_addr a4;
      struct in6_addr a6;
      if (inet_pton(AF_INET, (*list)[i].ip, &a4) != 1 && inet_pton(AF_INET6, (*list)[i].ip, &a6) != 1) bad = (*list)[i].ip;
    }
  }
  if (bad) {
    syslog(LOG_ERR, "[Config] %s: alias-resolver: '%.64s' is not an IP address (or the list has more than %d entries)", where, bad,
           KARIDNS_ALIAS_RESOLVERS_MAX);
    fprintf(stderr, "[ERROR] %s: alias-resolver: '%.64s' is not an IP address (or the list has more than %d entries)\n", where, bad,
            KARIDNS_ALIAS_RESOLVERS_MAX);
    if (ctx) ctx->error_occurred = true;
    return -1;
  }
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
  rrl->nodata_per_second = 0;
  rrl->nodata_per_second_set = false;
  rrl->nxdomains_per_second = 0;
  rrl->errors_per_second = 0;
  rrl->referrals_per_second = 0;
  rrl->referrals_per_second_set = false;
  rrl->all_per_second = 0;
  rrl->ipv4_prefix_length = 24;
  rrl->ipv6_prefix_length = 56;
  rrl->ipv4_prefix_length_set = false;
  rrl->ipv6_prefix_length_set = false;
  rrl->window_seconds = 15;
  rrl->slip = 2;
  rrl->exempt_clients = NULL;
  rrl->exempt_clients_count = 0;
  rrl->exempt_clients_parsed = NULL;

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
    char *key = tok.value;
    tok.value = NULL;
    free_token(&tok);

    if (strcmp(key, "exempt-clients") == 0) {
      if (parse_ip_port_list(ctx, "rate-limit exempt-clients", &rrl->exempt_clients, &rrl->exempt_clients_count) != 0) {
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
    char *val = tok.value;
    tok.value = NULL;
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
    } else if (strcmp(key, "nodata-per-second") == 0) {
      if (valid) {
        rrl->nodata_per_second = (int)num_val;
        rrl->nodata_per_second_set = true;
      } else {
        syslog(LOG_WARNING, "[Config] Invalid value '%s' for rate-limit option '%s', ignoring", val, key);
      }
    } else if (strcmp(key, "nxdomains-per-second") == 0) {
      if (valid) rrl->nxdomains_per_second = (int)num_val;
      else syslog(LOG_WARNING, "[Config] Invalid value '%s' for rate-limit option '%s', ignoring", val, key);
    } else if (strcmp(key, "errors-per-second") == 0) {
      if (valid) rrl->errors_per_second = (int)num_val;
      else syslog(LOG_WARNING, "[Config] Invalid value '%s' for rate-limit option '%s', ignoring", val, key);
    } else if (strcmp(key, "referrals-per-second") == 0) {
      if (valid) {
        rrl->referrals_per_second = (int)num_val;
        rrl->referrals_per_second_set = true;
      } else {
        syslog(LOG_WARNING, "[Config] Invalid value '%s' for rate-limit option '%s', ignoring", val, key);
      }
    } else if (strcmp(key, "all-per-second") == 0) {
      if (valid) rrl->all_per_second = (int)num_val;
      else syslog(LOG_WARNING, "[Config] Invalid value '%s' for rate-limit option '%s', ignoring", val, key);
    } else if (strcmp(key, "ipv4-prefix-length") == 0 || strcmp(key, "ipv6-prefix-length") == 0) {
      /* D-05: BIND と同じ名前と範囲 (IPv4 0-32、IPv6 0-128) */
      bool v4 = (key[3] == '4');
      long max_len = v4 ? 32 : 128;
      if (valid && num_val <= max_len) {
        if (v4) {
          rrl->ipv4_prefix_length = (uint8_t)num_val;
          rrl->ipv4_prefix_length_set = true;
        } else {
          rrl->ipv6_prefix_length = (uint8_t)num_val;
          rrl->ipv6_prefix_length_set = true;
        }
      } else {
        syslog(LOG_WARNING, "[Config] Invalid value '%s' for rate-limit option '%s' (0-%ld), ignoring",
               val, key, max_len);
      }
    } else if (strcmp(key, "qps-scale") == 0 || strcmp(key, "min-table-size") == 0 ||
               strcmp(key, "max-table-size") == 0) {
      /* BIND の設定をそのまま読めるように受け付けるが、表は固定長でこれらは効かない (D-05) */
      syslog(LOG_WARNING, "[Config] rate-limit option '%s' is accepted for BIND compatibility but has no effect", key);
    } else if (strcmp(key, "window") == 0) {
      if (*endptr == '\0' && num_val > 0) rrl->window_seconds = (int)num_val;
      else syslog(LOG_WARNING, "[Config] Invalid value '%s' for rate-limit option '%s', ignoring", val, key);
    } else if (strcmp(key, "slip") == 0) {
      if (valid) rrl->slip = (int)num_val;
      else syslog(LOG_WARNING, "[Config] Invalid value '%s' for rate-limit option '%s', ignoring", val, key);
    } else if (strcmp(key, "log-only") == 0 || strcmp(key, "early-drop") == 0) {
      bool *dst = (strcmp(key, "log-only") == 0) ? &rrl->log_only : &rrl->early_drop;
      if (!parse_config_bool(val, dst)) {
        report_bad_bool(ctx, NULL, key, val);
        free(key);
        free(val);
        return -1;
      }
    } else {
      syslog(LOG_WARNING, "[Config] Unknown rate-limit option '%s'", key);
    }
    free(key);
    free(val);
  }

  if (!rrl->nodata_per_second_set) {
    // nodata-per-second が明示指定されていない場合は responses-per-second を流用する
    // （既存設定ファイルの後方互換のためのデフォルト）
    rrl->nodata_per_second = rrl->responses_per_second;
  }
  if (!rrl->referrals_per_second_set) {
    // referrals-per-second も同じ (BIND の既定と同じ)
    rrl->referrals_per_second = rrl->responses_per_second;
  }
  
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) {
    free_token(&tok);
    return -1;
  }
  free_token(&tok);

  if (rrl->exempt_clients_count > 0 && rrl->exempt_clients) {
    rrl->exempt_clients_parsed = calloc(rrl->exempt_clients_count, sizeof(cidr_entry_t));
    if (rrl->exempt_clients_parsed) {
      for (int i = 0; i < rrl->exempt_clients_count; i++) {
        cidr_entry_parse(&rrl->exempt_clients_parsed[i], rrl->exempt_clients[i].ip);
      }
    }
  }

  return 0;
}

static int parse_ecs_tags_block(token_ctx_t *ctx, ecs_tag_def_t **out_tags, int *out_count) {
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
    if (tok.type != TOKEN_STRING || strcmp(tok.value, "tag") != 0) {
      free_token(&tok);
      return -1;
    }
    free_token(&tok);

    tok = get_next_token(ctx);
    if (tok.type != TOKEN_STRING) {
      free_token(&tok);
      return -1;
    }
    char *tag_name = tok.value;
    tok.value = NULL;
    free_token(&tok);

    tok = get_next_token(ctx);
    if (tok.type != TOKEN_LBRACE) {
      free(tag_name);
      free_token(&tok);
      return -1;
    }
    free_token(&tok);

    ecs_cidr_entry_t *cidrs = NULL;
    int cidr_count = 0;
    bool cidr_err = false;
    while (1) {
      tok = get_next_token(ctx);
      if (tok.type == TOKEN_RBRACE) {
        free_token(&tok);
        break;
      }
      if (tok.type != TOKEN_STRING) {
        free_token(&tok);
        cidr_err = true;
        break;
      }
      ecs_cidr_entry_t *new_cidrs = safe_realloc_or_die(cidrs, sizeof(ecs_cidr_entry_t) * (cidr_count + 1));
      if (!new_cidrs) {
        free_token(&tok);
        cidr_err = true;
        break;
      }
      cidrs = new_cidrs;
      memset(&cidrs[cidr_count], 0, sizeof(ecs_cidr_entry_t));
      cidrs[cidr_count].cidr = tok.value;
      tok.value = NULL;
      free_token(&tok);
      if (cidrs[cidr_count].cidr) {
        cidr_entry_parse(&cidrs[cidr_count].parsed, cidrs[cidr_count].cidr);
      }
      cidr_count++;

      tok = get_next_token(ctx);
      if (tok.type != TOKEN_SEMICOLON) {
        free_token(&tok);
        cidr_err = true;
        break;
      }
      free_token(&tok);
    }
    if (cidr_err) {
      free(tag_name);
      for (int c = 0; c < cidr_count; c++) free(cidrs[c].cidr);
      free(cidrs);
      return -1;
    }

    tok = get_next_token(ctx);
    if (tok.type != TOKEN_SEMICOLON) {
      free(tag_name);
      for (int c = 0; c < cidr_count; c++) free(cidrs[c].cidr);
      free(cidrs);
      free_token(&tok);
      return -1;
    }
    free_token(&tok);

    ecs_tag_def_t *new_out_tags = safe_realloc_or_die(*out_tags, sizeof(ecs_tag_def_t) * (*out_count + 1));
    if (!new_out_tags) {
      free(tag_name);
      for (int c = 0; c < cidr_count; c++) free(cidrs[c].cidr);
      free(cidrs);
      return -1;
    }
    *out_tags = new_out_tags;
    (*out_tags)[*out_count].tag = tag_name;
    (*out_tags)[*out_count].cidrs = cidrs;
    (*out_tags)[*out_count].cidr_count = cidr_count;
    (*out_count)++;
  }

  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) {
    free_token(&tok);
    return -1;
  }
  free_token(&tok);
  return 0;
}

/* tcp-mss / tcp-window / udp-bufsize / zone-tcp-* / zone-udp-bufsize の値を1つ読み、
 * 終端の ';' まで消費する。allow_suffix なら K/M 接尾辞 (1024 倍) を受け付ける。
 * parse_buffer_size_value() と違い、末尾のゴミや範囲外の値を丸めずに拒否する
 * (黙って OS 既定値のまま動くと、意図した性能設定が効いていないことに気付けない)。 */
static int parse_transport_param(token_ctx_t *ctx, const char *zone_domain, const char *name,
                                 bool allow_suffix, long long lo, long long hi, int *out) {
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_STRING || !tok.value) {
    free_token(&tok);
    return -1;
  }
  const char *s = tok.value;
  bool ok = false;
  long long v = 0;
  if (isdigit((unsigned char)s[0])) {
    char *end = NULL;
    errno = 0;
    v = strtoll(s, &end, 10);
    if (errno == 0) {
      long long mult = 1;
      if (allow_suffix && (*end == 'k' || *end == 'K')) { mult = 1024LL; end++; }
      else if (allow_suffix && (*end == 'm' || *end == 'M')) { mult = 1024LL * 1024; end++; }
      if (*end == '\0' && v <= hi / mult) {
        v *= mult;
        ok = (v >= lo && v <= hi);
      }
    }
  }
  if (!ok) {
    const char *suffix_hint = allow_suffix ? ", K/M suffix allowed" : "";
    char loc[300] = "";
    if (ctx) {
      ctx_location(ctx, loc, sizeof(loc) - 2);
      strlcat(loc, ": ", sizeof(loc));
    }
    if (zone_domain) {
      syslog(LOG_ERR, "[Config] %szone '%s': invalid %s value '%s' (expected %lld..%lld%s)",
             loc, zone_domain, name, s, lo, hi, suffix_hint);
      fprintf(stderr, "[ERROR] %szone '%s': invalid %s value '%s' (expected %lld..%lld%s)\n",
              loc, zone_domain, name, s, lo, hi, suffix_hint);
    } else {
      syslog(LOG_ERR, "[Config] %sInvalid %s value '%s' (expected %lld..%lld%s)", loc, name, s, lo, hi, suffix_hint);
      fprintf(stderr, "[ERROR] %sInvalid %s value '%s' (expected %lld..%lld%s)\n", loc, name, s, lo, hi, suffix_hint);
    }
    free_token(&tok);
    if (ctx) ctx->error_occurred = true;
    return -1;
  }
  free_token(&tok);
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) {
    free_token(&tok);
    return -1;
  }
  free_token(&tok);
  *out = (int)v;
  return 0;
}

/* ---- Batch 7: BIND names for settings KariDNS already has, max-udp-size at the options / view level, require-server-cookie.
 *   udp-receive-buffer / udp-send-buffer = udp-recvbuf-size / udp-sndbuf-size (the same value written under both names is fine, two values are
 *   a mistake: which one would win?);  max-udp-size = udp-bufsize (BIND 9.20 bin/named/server.c: the value is held to 512..4096);
 *   tcp-receive-buffer / tcp-send-buffer set the two directions that tcp-window sets together.  BIND holds a non-zero buffer size to at least 4096
 *   (CAP_IF_NOT_ZERO in configure_server_options()); 0 is the system's size, which for UDP is KariDNS's own default here. ---- */
static int alias_note(token_ctx_t *ctx, server_config_t *cfg, int slot, const char *key, long v) {
  char loc[64], cur[300];
  ctx_location(ctx, cur, sizeof(cur));
  snprintf(loc, sizeof(loc), "%s", cur);
  if (cfg->alias_note[slot].name[0] && strcmp(cfg->alias_note[slot].name, key) != 0 && cfg->alias_note[slot].v != v) {
    conf_error(ctx, "options", "%s %ld and %s %ld (%s) are the same setting with two values; write one of them, or the same value in both", key, v,
               cfg->alias_note[slot].name, cfg->alias_note[slot].v, cfg->alias_note[slot].loc);
    return -1;
  }
  snprintf(cfg->alias_note[slot].name, sizeof(cfg->alias_note[slot].name), "%s", key);
  cfg->alias_note[slot].v = v;
  snprintf(cfg->alias_note[slot].loc, sizeof(cfg->alias_note[slot].loc), "%s", loc);
  return 0;
}

/* A BIND buffer size: an integer (the K / M suffix of KariDNS is read too); 0 = the system's.  *out is the size, held to at least 4096 unless 0. */
static int parse_bind_bufsize(token_ctx_t *ctx, const char *key, int *out) {
  int v = 0;
  if (parse_transport_param(ctx, NULL, key, true, 0, INT_MAX, &v) != 0) return -1;
  if (v > 0 && v < 4096) v = 4096;
  *out = v;
  return 0;
}

static int parse_udp_size_option(token_ctx_t *ctx, server_config_t *cfg, const char *what, const char *key, uint16_t *out) {
  int v = 0;
  if (parse_transport_param(ctx, NULL, key, false, 0, INT_MAX, &v) != 0) return -1;
  if (v < 512 || v > 4096) {   /* bin/named/server.c: the value is raised to 512 or lowered to 4096 */
    int held = v < 512 ? 512 : 4096;
    conf_warn_here(ctx, what, "%s %d is out of range (512..4096): %s %d", key, v, v < 512 ? "raising to" : "lowering to", held);
    v = held;
  }
  if (cfg && alias_note(ctx, cfg, 0, key, v) != 0) return -1;
  *out = (uint16_t)v;
  return 0;
}

const view_config_t *config_find_view(const server_config_t *cfg, const char *name) {
  if (!cfg || !name || !name[0]) return NULL;
  for (const view_config_t *v = cfg->views; v; v = v->next)
    if (strcasecmp(v->name, name) == 0) return v;
  return NULL;
}

bool config_require_server_cookie(const server_config_t *cfg, const char *view_name) {
  if (!cfg) return false;
  if (cfg->any_view_cookie) {
    const view_config_t *v = config_find_view(cfg, view_name);
    if (v && v->require_cookie_set) return v->require_cookie;
  }
  return cfg->require_server_cookie;
}

/* notify-retries / notify-retry-interval / notify-retry-backoff / notify-tcp-timeout。options (zone_domain NULL) と zone で共通。
 * 戻り値: 0 = このキーではない、1 = 読んで nr に設定した、-1 = 値が不正 (ログ済み)。 */
static int parse_notify_retry_option(token_ctx_t *ctx, const char *zone_domain, const char *key,
                                     notify_retry_config_t *nr) {
  if (strcmp(key, "notify-retries") == 0) {
    if (parse_transport_param(ctx, zone_domain, key, false, 0, NOTIFY_RETRIES_MAX, &nr->retries) != 0) return -1;
    nr->retries_set = true;
    return 1;
  }
  if (strcmp(key, "notify-retry-interval") == 0) {
    if (parse_transport_param(ctx, zone_domain, key, false, 1, NOTIFY_RETRY_INTERVAL_MAX, &nr->interval) != 0)
      return -1;
    nr->interval_set = true;
    return 1;
  }
  if (strcmp(key, "notify-tcp-timeout") == 0) {
    if (parse_transport_param(ctx, zone_domain, key, false, 1, NOTIFY_TCP_TIMEOUT_MAX, &nr->tcp_timeout) != 0) return -1;
    nr->tcp_timeout_set = true;
    return 1;
  }
  if (strcmp(key, "notify-retry-backoff") != 0) return 0;
  conf_token_t tok = get_next_token(ctx);
  bool ok = tok.type == TOKEN_STRING && tok.value &&
            (strcasecmp(tok.value, "fixed") == 0 || strcasecmp(tok.value, "exponential") == 0);
  if (!ok) {
    const char *v = (tok.type == TOKEN_STRING && tok.value) ? tok.value : "";
    if (zone_domain) {
      syslog(LOG_ERR, "[Config] zone '%s': invalid notify-retry-backoff value '%s' (expected fixed or exponential)",
             zone_domain, v);
      fprintf(stderr, "[ERROR] zone '%s': invalid notify-retry-backoff value '%s' (expected fixed or exponential)\n",
              zone_domain, v);
    } else {
      syslog(LOG_ERR, "[Config] Invalid notify-retry-backoff value '%s' (expected fixed or exponential)", v);
      fprintf(stderr, "[ERROR] Invalid notify-retry-backoff value '%s' (expected fixed or exponential)\n", v);
    }
    free_token(&tok);
    if (ctx) ctx->error_occurred = true;
    return -1;
  }
  nr->backoff = strcasecmp(tok.value, "exponential") == 0 ? NOTIFY_BACKOFF_EXPONENTIAL : NOTIFY_BACKOFF_FIXED;
  nr->backoff_set = true;
  free_token(&tok);
  tok = get_next_token(ctx);
  bool semi = tok.type == TOKEN_SEMICOLON;
  free_token(&tok);
  return semi ? 1 : -1;
}

notify_retry_config_t notify_retry_effective(const server_config_t *cfg, const zone_config_t *zone) {
  notify_retry_config_t r = {NOTIFY_RETRIES_DEFAULT, NOTIFY_RETRY_INTERVAL_DEFAULT, NOTIFY_BACKOFF_FIXED,
                             NOTIFY_TCP_TIMEOUT_DEFAULT, true, true, true, true};
  if (cfg) {
    r.retries = cfg->notify_retry.retries;
    r.interval = cfg->notify_retry.interval;
    r.backoff = cfg->notify_retry.backoff;
    r.tcp_timeout = cfg->notify_retry.tcp_timeout;
  }
  if (zone) {
    const zone_ext_t *x = zext(zone);
    if (x->notify_retry.retries_set) r.retries = x->notify_retry.retries;
    if (x->notify_retry.interval_set) r.interval = x->notify_retry.interval;
    if (x->notify_retry.backoff_set) r.backoff = x->notify_retry.backoff;
    if (x->notify_retry.tcp_timeout_set) r.tcp_timeout = x->notify_retry.tcp_timeout;
  }
  return r;
}

int ixfr_history_effective(const server_config_t *cfg, const zone_config_t *zone) {
  if (zone && zext(zone)->ixfr_history_set) return zext(zone)->ixfr_history;
  return cfg ? cfg->ixfr_history : IXFR_HISTORY_DEFAULT;
}

void xfr_zone_limits(const server_config_t *cfg, const zone_config_t *zone, uint64_t *max_records, uint64_t *max_bytes) {
  uint64_t r = cfg && cfg->max_zone_records ? cfg->max_zone_records : KARIDNS_DB_MAX_ZONE_RECORDS_DEFAULT;
  uint64_t b = cfg && cfg->max_zone_bytes ? cfg->max_zone_bytes : KARIDNS_DB_MAX_ZONE_BYTES_DEFAULT;
  if (zone && zext(zone)->max_zone_records) r = zext(zone)->max_zone_records;
  if (zone && zext(zone)->max_zone_bytes) b = zext(zone)->max_zone_bytes;
  *max_records = r;
  *max_bytes = b;
}

static int db_take_uint(token_ctx_t *ctx, const char *key, bool allow_suffix, uint64_t lo, uint64_t hi, uint64_t *out);

/* ---- Batch 4: the transfer / NOTIFY options of options { }, view { } and zone { } (BIND 9.20 ARM "Zone Transfers", "Boolean Options"
 * and the zone statement; defaults from bin/named/config.c, ranges from lib/isccfg/check.c) ---- */

static const struct { const char *name; uint32_t bit; int src; } k_xo_options[] = {
  {"notify-source", 0, XSRC_NOTIFY4}, {"notify-source-v6", 0, XSRC_NOTIFY6}, {"transfer-source", 0, XSRC_XFER4},
  {"transfer-source-v6", 0, XSRC_XFER6},
  {"min-refresh-time", XO_MIN_REFRESH, -1}, {"max-refresh-time", XO_MAX_REFRESH, -1}, {"min-retry-time", XO_MIN_RETRY, -1},
  {"max-retry-time", XO_MAX_RETRY, -1}, {"max-transfer-time-in", XO_XFER_TIME_IN, -1}, {"max-transfer-idle-in", XO_XFER_IDLE_IN, -1},
  {"max-transfer-time-out", XO_XFER_TIME_OUT, -1}, {"max-transfer-idle-out", XO_XFER_IDLE_OUT, -1},
  {"notify-delay", XO_NOTIFY_DELAY, -1}, {"notify-to-soa", XO_B_NOTIFY_TO_SOA, -1}, {"try-tcp-refresh", XO_B_TRY_TCP_REFRESH, -1},
  {"request-ixfr", XO_B_REQUEST_IXFR, -1}, {"provide-ixfr", XO_B_PROVIDE_IXFR, -1}, {"request-expire", XO_B_REQUEST_EXPIRE, -1},
  {"multi-master", XO_B_MULTI_MASTER, -1},
};

/* ---- Batch 7: max-records, max-records-per-type, max-types-per-name, max-zone-ttl, serial-update-method, masterfile-format and the check-* family
 * in options { }, view { } and zone { }.  Grammar from BIND 9.20.4 lib/isccfg/namedconf.c (zone_clauses, view_clauses, checknames_fields,
 * checkmode_enums, warn_enums, masterformat_enums, maxduration), defaults from bin/named/config.c. ---- */
static const struct { const char *name; int chk; } k_zv_checks[] = {   /* chk >= 0: ZC_*; the kind of value is in parse_zv_option() */
  {"check-dup-records", ZC_DUP_RECORDS}, {"check-integrity", ZC_INTEGRITY}, {"check-mx", ZC_MX}, {"check-mx-cname", ZC_MX_CNAME},
  {"check-sibling", ZC_SIBLING}, {"check-spf", ZC_SPF}, {"check-srv-cname", ZC_SRV_CNAME}, {"check-svcb", ZC_SVCB}, {"check-wildcard", ZC_WILDCARD},
};

static bool zv_option_name(const char *key) {
  static const char *const names[] = { "max-records", "max-records-per-type", "max-types-per-name", "max-zone-ttl", "serial-update-method",
                                       "masterfile-format", "check-names", NULL };
  for (size_t i = 0; names[i]; i++)
    if (strcmp(names[i], key) == 0) return true;
  for (size_t i = 0; i < sizeof(k_zv_checks) / sizeof(k_zv_checks[0]); i++)
    if (strcmp(k_zv_checks[i].name, key) == 0) return true;
  return false;
}

/* fail / warn / ignore (checkmode); allow_fail = false: warn / ignore only (warn_enums, check-spf) */
static bool zv_parse_mode(const char *s, bool allow_fail, uint8_t *out) {
  if (strcasecmp(s, "warn") == 0) { *out = CHK_WARN; return true; }
  if (strcasecmp(s, "ignore") == 0) { *out = CHK_IGNORE; return true; }
  if (allow_fail && strcasecmp(s, "fail") == 0) { *out = CHK_FAIL; return true; }
  return false;
}

/* a non-negative integer of at most 10 digits that fits in 32 bits (cfg_type_uint32) */
static bool zv_parse_u32(const char *s, uint32_t *out) {
  size_t n = 0;
  while (s[n] >= '0' && s[n] <= '9') n++;
  if (n == 0 || n > 10 || s[n] != '\0') return false;
  unsigned long long v = strtoull(s, NULL, 10);
  if (v > UINT32_MAX) return false;
  *out = (uint32_t)v;
  return true;
}

/* One statement of this family: `key` has been read and zv_option_name(key) holds.  The value and the ';' are read here.  A later statement of
 * the same name replaces the earlier one.  0 = done, -1 = error (reported).  zone_level: the zone { } form of check-names (a bare mode). */
static int parse_zv_option(token_ctx_t *ctx, const char *what, const char *key, zone_vopts_t *zv, bool zone_level) {
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_STRING || !tok.value) { free_token(&tok); return -1; }
  uint32_t u = 0;
  uint8_t mode = 0;
  if (strcmp(key, "max-records") == 0 || strcmp(key, "max-records-per-type") == 0 || strcmp(key, "max-types-per-name") == 0) {
    if (!zv_parse_u32(tok.value, &u)) {
      conf_error(ctx, what, "%s: invalid value '%.64s' (expected an integer from 0 to 4294967295; 0 is no limit)", key, tok.value);
      free_token(&tok);
      return -1;
    }
    if (strcmp(key, "max-records") == 0) { zv->max_records = u; zv->set |= ZV_MAX_RECORDS; }
    else if (strcmp(key, "max-records-per-type") == 0) { zv->max_per_type = u; zv->set |= ZV_MAX_PER_TYPE; }
    else { zv->max_types_per_name = u; zv->set |= ZV_MAX_TYPES_PER_NAME; }
  } else if (strcmp(key, "max-zone-ttl") == 0) {
    /* maxduration: `unlimited`, or a duration -- ISO 8601 (P1D) or a TTL value (1d, 3600).  Only the TTL form is read; an ISO 8601 value is
     * refused rather than guessed. */
    if (strcasecmp(tok.value, "unlimited") == 0) {
      u = 0;
    } else if (tok.value[0] == 'P' || tok.value[0] == 'p') {
      conf_error(ctx, what, "max-zone-ttl: ISO 8601 durations (\"%.32s\") are not supported; write the value in seconds or with the units s, m, h, d, w (for example 1d)",
                 tok.value);
      free_token(&tok);
      return -1;
    } else if (!parse_ttl_strict(tok.value, UINT32_MAX, &u)) {
      conf_error(ctx, what, "max-zone-ttl: invalid value '%.64s' (expected unlimited, a number of seconds, or a TTL with the units s, m, h, d, w)", tok.value);
      free_token(&tok);
      return -1;
    }
    zv->max_zone_ttl = u;
    zv->set |= ZV_MAX_ZONE_TTL;
  } else if (strcmp(key, "serial-update-method") == 0) {
    if (strcasecmp(tok.value, "increment") == 0) zv->serial_method = SUM_INCREMENT;
    else if (strcasecmp(tok.value, "unixtime") == 0) zv->serial_method = SUM_UNIXTIME;
    else if (strcasecmp(tok.value, "date") == 0) zv->serial_method = SUM_DATE;
    else {
      conf_error(ctx, what, "serial-update-method: invalid value '%.64s' (expected increment, unixtime or date)", tok.value);
      free_token(&tok);
      return -1;
    }
    zv->set |= ZV_SERIAL_METHOD;
  } else if (strcmp(key, "masterfile-format") == 0) {
    /* masterformat_enums: raw, text.  KariDNS reads text zone files only; a raw file read as text would fail in a confusing way (or be
     * taken for something else), so raw is refused here (decision 2026-10-29). */
    if (strcasecmp(tok.value, "raw") == 0) {
      conf_error(ctx, what, "masterfile-format raw is not supported: KariDNS reads zone files in text format only (masterfile-format text)");
      free_token(&tok);
      return -1;
    }
    if (strcasecmp(tok.value, "text") != 0) {
      conf_error(ctx, what, "masterfile-format: invalid value '%.64s' (expected text or raw; only text is supported)", tok.value);
      free_token(&tok);
      return -1;
    }
  } else if (strcmp(key, "check-names") == 0) {
    int ci = -1;
    if (!zone_level) {   /* options / view: check-names (primary | master | secondary | slave | response) (fail | warn | ignore) */
      if (strcasecmp(tok.value, "primary") == 0 || strcasecmp(tok.value, "master") == 0) ci = ZC_NAMES_PRIMARY;
      else if (strcasecmp(tok.value, "secondary") == 0 || strcasecmp(tok.value, "slave") == 0) ci = ZC_NAMES_SECONDARY;
      else if (strcasecmp(tok.value, "response") == 0) ci = ZC_NAMES_RESPONSE;
      else {
        conf_error(ctx, what, "check-names: invalid type '%.64s' (expected primary, master, secondary, slave or response)", tok.value);
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_STRING || !tok.value) { free_token(&tok); return -1; }
    }
    if (!zv_parse_mode(tok.value, true, &mode)) {
      conf_error(ctx, what, "check-names: invalid mode '%.64s' (expected fail, warn or ignore)", tok.value);
      free_token(&tok);
      return -1;
    }
    if (zone_level) { zv->zone_check_names = mode; zv->set |= ZV_ZONE_CHECK_NAMES; }
    else { zv->chk[ci] = mode; zv->set |= ZV_CHK(ci); }
  } else {
    int ci = -1;
    for (size_t i = 0; i < sizeof(k_zv_checks) / sizeof(k_zv_checks[0]); i++)
      if (strcmp(k_zv_checks[i].name, key) == 0) ci = k_zv_checks[i].chk;
    bool boolean = ci == ZC_INTEGRITY || ci == ZC_SIBLING || ci == ZC_SVCB || ci == ZC_WILDCARD;   /* cfg_type_boolean */
    bool b;
    if (boolean ? parse_config_bool(tok.value, &b) : zv_parse_mode(tok.value, ci != ZC_SPF, &mode)) {
      if (boolean) mode = b ? CHK_FAIL : CHK_IGNORE;
      zv->chk[ci] = mode;
      zv->set |= ZV_CHK(ci);
    } else {
      conf_error(ctx, what, "%s: invalid value '%.64s' (expected %s)", key, tok.value, boolean ? "yes or no" : ci == ZC_SPF ? "warn or ignore" : "fail, warn or ignore");
      free_token(&tok);
      return -1;
    }
    /* checks that KariDNS does not have: the value is read, and said to have no effect (nothing is checked, nothing is silently different) */
    if (ci == ZC_SIBLING || ci == ZC_SVCB || ci == ZC_SPF)
      conf_warn_here(ctx, what, "%s is accepted, no effect in KariDNS (zone_lint has no such check)", key);
  }
  free_token(&tok);
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) { free_token(&tok); return -1; }
  free_token(&tok);
  return 0;
}

static bool fstrm_option_name(const char *key) {
  static const char *const names[] = { "fstrm-set-buffer-hint", "fstrm-set-flush-timeout", "fstrm-set-input-queue-size", "fstrm-set-output-notify-threshold",
                                       "fstrm-set-output-queue-model", "fstrm-set-output-queue-size", "fstrm-set-reopen-interval", NULL };
  for (size_t i = 0; names[i]; i++)
    if (strcmp(names[i], key) == 0) return true;
  return false;
}

/* fstrm-set-*: uint32, fstrm-set-output-queue-model is mpsc or spsc, fstrm-set-reopen-interval a duration (lib/isccfg/namedconf.c) */
static int parse_fstrm_option(token_ctx_t *ctx, const char *key) {
  char what[48];
  snprintf(what, sizeof(what), "options %s", key);
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_STRING || !tok.value) { free_token(&tok); return -1; }
  uint32_t u;
  bool ok;
  if (strcmp(key, "fstrm-set-output-queue-model") == 0) ok = strcasecmp(tok.value, "mpsc") == 0 || strcasecmp(tok.value, "spsc") == 0;
  else if (strcmp(key, "fstrm-set-reopen-interval") == 0) ok = parse_ttl_strict(tok.value, UINT32_MAX, &u);
  else ok = zv_parse_u32(tok.value, &u);
  if (!ok) {
    conf_error(ctx, what, "invalid value '%.64s'", tok.value);
    free_token(&tok);
    return -1;
  }
  free_token(&tok);
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) { free_token(&tok); return -1; }
  free_token(&tok);
  conf_warn_here(ctx, what, "accepted, no effect in KariDNS: the dnstap writer has its own settings (dnstap { queue-size })");
  return 0;
}

/* ---- Batch 7: catalog-zones { zone "name" [default-primaries { .. }] [zone-directory "d"] [in-memory yes|no] [min-update-interval d]; ... }; in
 * options and view (BIND 9.20 lib/isccfg/namedconf.c catz_zone_fields; check.c check_catz(): a name is listed once).  KariDNS treats a zone as a
 * catalog zone with `catalog-zone yes;`; a listed name selects that zone (of every view for options, of the view for view) the same way.  The
 * other parts of the statement are read and said to have no effect: members take the primaries of the catalog zone, the member zones are
 * in memory, and the catalog zone is processed when it changes. ---- */
static void catz_names_free(char **names, int count) {
  for (int i = 0; i < count; i++) free(names[i]);
  free(names);
}

static int parse_catalog_zones(token_ctx_t *ctx, const char *what, char ***names, int *count) {
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_LBRACE) { free_token(&tok); return -1; }
  free_token(&tok);
  for (;;) {
    tok = get_next_token(ctx);
    if (tok.type == TOKEN_RBRACE) { free_token(&tok); break; }
    if (tok.type != TOKEN_STRING || !tok.value || strcmp(tok.value, "zone") != 0) {
      conf_error(ctx, what, "catalog-zones: expected `zone \"name\"`, found '%.64s'", tok.type == TOKEN_STRING && tok.value ? tok.value : "(not a word)");
      free_token(&tok);
      return -1;
    }
    free_token(&tok);
    tok = get_next_token(ctx);
    if (tok.type != TOKEN_STRING || !tok.value) { free_token(&tok); return -1; }
    char *name = tok.value;
    tok.value = NULL;
    free_token(&tok);
    for (int i = 0; i < *count; i++)
      if (domain_names_match_ci((*names)[i], name)) {
        conf_error(ctx, what, "catalog zone '%.200s' is listed twice", name);   /* check.c: "catalog zone '%s': already added here" */
        free(name);
        return -1;
      }
    char **nn = realloc(*names, ((size_t)*count + 1) * sizeof(char *));
    if (!nn) { free(name); if (ctx) ctx->error_occurred = true; return -1; }
    *names = nn;
    nn[(*count)++] = name;
    bool primaries = false;
    for (;;) {
      tok = get_next_token(ctx);
      if (tok.type == TOKEN_SEMICOLON) { free_token(&tok); break; }
      if (tok.type != TOKEN_STRING || !tok.value) { free_token(&tok); return -1; }
      char key[32];
      snprintf(key, sizeof(key), "%.31s", tok.value);
      free_token(&tok);
      if (strcmp(key, "default-primaries") == 0 || strcmp(key, "default-masters") == 0) {
        if (primaries) {   /* check.c: 'default-primaries' and 'default-masters' can not be both defined */
          conf_error(ctx, what, "catalog zone '%.200s': 'default-primaries' and 'default-masters' can not be both defined", name);
          return -1;
        }
        primaries = true;
        tok = get_next_token(ctx);
        if (tok.type != TOKEN_LBRACE) { free_token(&tok); return -1; }
        free_token(&tok);
        int depth = 1;
        while (depth > 0) {
          tok = get_next_token(ctx);
          if (tok.type == TOKEN_EOF) { free_token(&tok); return -1; }
          if (tok.type == TOKEN_LBRACE) depth++;
          else if (tok.type == TOKEN_RBRACE) depth--;
          free_token(&tok);
        }
        conf_warn_here(ctx, what, "catalog zone '%.200s': default-primaries is accepted, no effect in KariDNS: members are transferred from the primaries of the catalog zone", name);
      } else if (strcmp(key, "zone-directory") == 0 || strcmp(key, "in-memory") == 0 || strcmp(key, "min-update-interval") == 0) {
        tok = get_next_token(ctx);
        if (tok.type != TOKEN_STRING || !tok.value) { free_token(&tok); return -1; }
        bool bad = false;
        if (key[0] == 'i') {
          bool b;
          if (!parse_config_bool(tok.value, &b)) bad = true;
          else if (b) conf_warn_here(ctx, what, "catalog zone '%.200s': in-memory yes is how KariDNS always works (member zones are never written to files)", name);
          else conf_warn_here(ctx, what, "catalog zone '%.200s': in-memory no is accepted, no effect in KariDNS (member zones are never written to files)", name);
        } else if (key[0] == 'm') {
          uint32_t u;
          if (!parse_ttl_strict(tok.value, UINT32_MAX, &u)) bad = true;
          else conf_warn_here(ctx, what, "catalog zone '%.200s': min-update-interval is accepted, no effect in KariDNS", name);
        } else {
          conf_warn_here(ctx, what, "catalog zone '%.200s': zone-directory is accepted, no effect in KariDNS (member zones are never written to files)", name);
        }
        if (bad) conf_error(ctx, what, "catalog zone '%.200s': invalid %s '%.64s'", name, key, tok.value);
        free_token(&tok);
        if (bad) return -1;
      } else {
        conf_error(ctx, what, "catalog zone '%.200s': unknown option '%.64s'", name, key);
        return -1;
      }
    }
  }
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) { free_token(&tok); return -1; }
  free_token(&tok);
  return 0;
}

/* when the parse ends: the zones the lists name are catalog zones.  A name that is no zone of the scope is said (BIND would find no zone to
 * process either); the options list covers every view. */
static void catz_apply(token_ctx_t *ctx, server_config_t *cfg) {
  char loc[300];
  ctx_location(ctx, loc, sizeof(loc));
  for (int i = 0; i < cfg->catz_count; i++) {
    bool found = false;
    for (view_config_t *v = cfg->views; v; v = v->next) {
      zone_config_t *z = view_find_zone_config(v, cfg->catz_names[i]);
      if (z) { z->is_catalog = true; found = true; }
    }
    if (!found) conf_warn_loc(loc, "options catalog-zones", "'%.200s' is not a zone of the configuration: nothing is processed as a catalog zone", cfg->catz_names[i]);
  }
  for (view_config_t *v = cfg->views; v; v = v->next)
    for (int i = 0; i < v->catz_count; i++) {
      zone_config_t *z = view_find_zone_config(v, v->catz_names[i]);
      if (z) z->is_catalog = true;
      else conf_warn_loc(loc, "view catalog-zones", "'%.200s' is not a zone of view '%.64s': nothing is processed as a catalog zone", v->catz_names[i], v->name);
    }
}

static const zone_vopts_t *zv_of_view(const server_config_t *cfg, const char *view_name) {
  if (!cfg || !view_name || !view_name[0]) return NULL;
  for (const view_config_t *v = cfg->views; v; v = v->next)
    if (strcasecmp(v->name, view_name) == 0) return &v->zv;
  return NULL;
}

void zone_vopts_effective(const server_config_t *cfg, const zone_config_t *zone, const char *view_name, zone_veff_t *out) {
  memset(out, 0, sizeof(*out));
  for (int i = 0; i < ZC_N; i++) out->chk[i] = CHK_DEFAULT;
  out->serial_method = SUM_INCREMENT;
  const zone_vopts_t *lv[3] = { zone ? &zext(zone)->zv : NULL, zv_of_view(cfg, view_name), cfg ? &cfg->zv : NULL };
  uint32_t done = 0;
  for (int i = 0; i < 3; i++) {
    const zone_vopts_t *l = lv[i];
    if (!l) continue;
    uint32_t w = l->set & ~done;
    if (w & ZV_MAX_RECORDS) out->max_records = l->max_records;
    if (w & ZV_MAX_PER_TYPE) out->max_per_type = l->max_per_type;
    if (w & ZV_MAX_TYPES_PER_NAME) out->max_types_per_name = l->max_types_per_name;
    if (w & ZV_MAX_ZONE_TTL) out->max_zone_ttl = l->max_zone_ttl;
    if (w & ZV_SERIAL_METHOD) out->serial_method = l->serial_method;
    for (int c = 0; c < ZC_N; c++)
      if (w & ZV_CHK(c)) out->chk[c] = l->chk[c];
    done |= l->set;
  }
  /* check-names: the zone's own value, else the primary / secondary one of the view, else of options (bin/named/zoneconf.c checknames()) */
  out->check_names = CHK_DEFAULT;
  if (zone && (zext(zone)->zv.set & ZV_ZONE_CHECK_NAMES)) {
    out->check_names = zext(zone)->zv.zone_check_names;
  } else {
    const char *type = zone && zone->type ? zone->type : "primary";
    int ci = (strcasecmp(type, "secondary") == 0 || strcasecmp(type, "slave") == 0) ? ZC_NAMES_SECONDARY : ZC_NAMES_PRIMARY;
    out->check_names = out->chk[ci];
  }
}

/* ---- Batch 7: update-policy { grant | deny <identity> <matchtype> [<name>] <rrtypes>; ... } in a primary zone (BIND 9.20 lib/isccfg/namedconf.c
 * grant_fields / matchtype_enums, bin/named/zoneconf.c configure_zone_ssutable(), lib/isccfg/check.c check_update_policy()).  The identity is the
 * name of the TSIG key that signed the UPDATE.  A rule of a kind KariDNS cannot evaluate is never taken as one: a `grant` is dropped with a warning
 * (the first matching rule decides, so dropping a grant can only refuse more than BIND does, never allow more), a `deny` is an error (dropping it
 * would allow what the file forbids).  `update-policy local;` needs BIND's session key and is an error.  A type count, `A(3)`, limits the RRs a
 * grant adds and is not enforced: an error rather than a grant wider than written. ---- */
static int parse_update_policy(token_ctx_t *ctx, const char *what, const char *zone_domain, zone_ext_t *x) {
  conf_token_t tok = get_next_token(ctx);
  if (tok.type == TOKEN_STRING && tok.value && strcasecmp(tok.value, "local") == 0) {
    conf_error(ctx, what, "update-policy local is not supported: it needs the session key of BIND's dynamic update (grant <key> zonesub ANY; with a key of the "
               "configuration does the same for a key you hold)");
    free_token(&tok);
    return -1;
  }
  if (tok.type != TOKEN_LBRACE) { free_token(&tok); return -1; }
  free_token(&tok);
  update_policy_t *pol = calloc(1, sizeof(*pol));
  if (!pol) { if (ctx) ctx->error_occurred = true; return -1; }
  for (;;) {
    tok = get_next_token(ctx);
    if (tok.type == TOKEN_RBRACE) { free_token(&tok); break; }
    if (tok.type != TOKEN_STRING || !tok.value) { free_token(&tok); free(pol); return -1; }
    bool grant;
    if (strcasecmp(tok.value, "grant") == 0) grant = true;
    else if (strcasecmp(tok.value, "deny") == 0) grant = false;
    else {
      conf_error(ctx, what, "update-policy: expected grant or deny, found '%.64s'", tok.value);
      free_token(&tok);
      free(pol);
      return -1;
    }
    free_token(&tok);
    update_rule_t rule;
    memset(&rule, 0, sizeof(rule));
    rule.grant = grant;
    char mt[32] = "";
    for (int field = 0; field < 3; field++) {   /* identity, matchtype, name (not for zonesub) */
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_STRING || !tok.value) { free_token(&tok); free(pol); return -1; }
      if (field == 0) {
        if (strlen(tok.value) >= sizeof(rule.identity)) {
          conf_error(ctx, what, "update-policy: the identity is too long");
          free_token(&tok);
          free(pol);
          return -1;
        }
        snprintf(rule.identity, sizeof(rule.identity), "%s", tok.value);
      } else if (field == 1) {
        snprintf(mt, sizeof(mt), "%.31s", tok.value);
      } else {
        if (strlen(tok.value) >= sizeof(rule.name)) {
          conf_error(ctx, what, "update-policy: the name is too long");
          free_token(&tok);
          free(pol);
          return -1;
        }
        snprintf(rule.name, sizeof(rule.name), "%s", tok.value);
      }
      free_token(&tok);
      if (field == 1 && strcasecmp(mt, "zonesub") == 0) {
        snprintf(rule.name, sizeof(rule.name), "%s", zone_domain);
        break;
      }
    }
    static const struct { const char *name; int type; } k_mt[] = { {"name", UPD_NAME}, {"subdomain", UPD_SUBDOMAIN}, {"zonesub", UPD_SUBDOMAIN},
        {"wildcard", UPD_WILDCARD}, {"self", UPD_SELF}, {"selfsub", UPD_SELFSUB}, {"selfwild", UPD_SELFWILD} };
    int mtype = -1;
    for (size_t i = 0; i < sizeof(k_mt) / sizeof(k_mt[0]); i++)
      if (strcasecmp(k_mt[i].name, mt) == 0) mtype = k_mt[i].type;
    static const char *const k_unsupported[] = { "6to4-self", "external", "krb5-self", "krb5-selfsub", "krb5-subdomain", "krb5-subdomain-self-rhs",
                                                 "ms-self", "ms-selfsub", "ms-subdomain", "ms-subdomain-self-rhs", "tcp-self", NULL };
    bool unsupported = false;
    for (size_t i = 0; k_unsupported[i]; i++)
      if (strcasecmp(k_unsupported[i], mt) == 0) unsupported = true;
    if (mtype < 0 && !unsupported) {
      conf_error(ctx, what, "update-policy: '%.31s' is not a match type", mt);
      free(pol);
      return -1;
    }
    rule.mtype = (uint8_t)(mtype < 0 ? 0 : mtype);
    rule.ident_wild = rule.identity[0] == '*' && rule.identity[1] == '.' && rule.identity[2];
    if (mtype == UPD_WILDCARD && !(rule.name[0] == '*' && rule.name[1] == '.' && rule.name[2])) {
      conf_error(ctx, what, "update-policy: a wildcard rule needs a name of the form *.suffix, found '%.64s'", rule.name);
      free(pol);
      return -1;
    }
    /* the types, up to the ';' */
    for (;;) {
      tok = get_next_token(ctx);
      if (tok.type == TOKEN_SEMICOLON) { free_token(&tok); break; }
      if (tok.type != TOKEN_STRING || !tok.value) { free_token(&tok); free(pol); return -1; }
      uint16_t t = strcasecmp(tok.value, "ANY") == 0 ? 255 : get_type_code(tok.value);
      if (strchr(tok.value, '(')) {
        conf_error(ctx, what, "update-policy: the count limit of '%.64s' is not supported (a grant would be wider than written)", tok.value);
        free_token(&tok);
        free(pol);
        return -1;
      }
      if (t == 0) {
        conf_error(ctx, what, "update-policy: '%.64s' is not a record type", tok.value);
        free_token(&tok);
        free(pol);
        return -1;
      }
      if (rule.ntypes >= UPD_TYPES_MAX) {
        conf_error(ctx, what, "update-policy: more than %d types in one rule (at '%.64s')", UPD_TYPES_MAX, tok.value);
        free_token(&tok);
        free(pol);
        return -1;
      }
      rule.types[rule.ntypes++] = t;
      free_token(&tok);
    }
    if (unsupported) {
      if (!grant) {
        conf_error(ctx, what, "update-policy: deny %s cannot be evaluated by KariDNS; ignoring it would allow what the file forbids", mt);
        free(pol);
        return -1;
      }
      conf_warn_here(ctx, what, "update-policy: grant %s is not supported (it needs Kerberos, the transport address or a helper); the rule is ignored, which refuses more than BIND would, never less", mt);
      continue;
    }
    if (pol->count >= UPD_RULES_MAX) {
      conf_error(ctx, what, "update-policy: more than %d rules", UPD_RULES_MAX);
      free(pol);
      return -1;
    }
    pol->rules[pol->count++] = rule;
  }
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) { free_token(&tok); free(pol); return -1; }
  free_token(&tok);
  free(x->upd_policy);
  x->upd_policy = pol;
  return 0;
}

/* when the parse ends: BIND check.c: 'allow-update' is ignored when 'update-policy' is present (an error in the same zone) */
static int upd_policy_check(token_ctx_t *ctx, server_config_t *cfg) {
  for (const view_config_t *v = cfg->views; v; v = v->next)
    for (const zone_config_t *z = v->zones; z; z = z->next) {
      const zone_ext_t *x = zext(z);
      if (x->upd_policy && (x->allow_update_count > 0 || x->acl.update)) {
        conf_error(ctx, "zone", "zone '%.200s': 'allow-update' is ignored when 'update-policy' is present", z->domain);
        return -1;
      }
    }
  return 0;
}

static bool xo_option_name(const char *key) {
  for (size_t i = 0; i < sizeof(k_xo_options) / sizeof(k_xo_options[0]); i++)
    if (strcmp(k_xo_options[i].name, key) == 0) return true;
  return false;
}

static void xo_free_fields(xfr_opts_t *xo) {
  if (!xo) return;
  for (int i = 0; i < XSRC_N; i++) free(xo->src[i].loc);
  memset(xo, 0, sizeof(*xo));
}

/* a deep copy of s into d (d is overwritten); false = out of memory */
static bool xo_copy(xfr_opts_t *d, const xfr_opts_t *s) {
  *d = *s;
  for (int i = 0; i < XSRC_N; i++) d->src[i].loc = NULL;
  for (int i = 0; i < XSRC_N; i++) {
    if (s->src[i].loc && !(d->src[i].loc = strdup(s->src[i].loc))) {
      xo_free_fields(d);
      return false;
    }
  }
  return true;
}

static xfr_opts_t *zone_xo_mut(zone_ext_t *x) {
  if (!x->xo) x->xo = calloc(1, sizeof(*x->xo));
  return x->xo;
}

/* One transfer / NOTIFY statement of a block: `key` has been read and is one of k_xo_options.  The value and the ';' are read here.
 * zone_level: the KariDNS zone statement `notify-source <address>` takes an address of either family (as before batch 4), and *legacy
 * receives a copy of the value for zext()->notify_source.  A later statement of the same name replaces the earlier one.  0 = done,
 * -1 = error (reported). */
static int parse_xfr_option(token_ctx_t *ctx, const char *what, const char *key, xfr_opts_t *xo, bool zone_level, char **legacy) {
  char loc[300], db[96];
  ctx_location(ctx, loc, sizeof(loc));
  size_t oi = 0;
  while (oi < sizeof(k_xo_options) / sizeof(k_xo_options[0]) && strcmp(k_xo_options[oi].name, key) != 0) oi++;
  if (oi == sizeof(k_xo_options) / sizeof(k_xo_options[0])) return -1;
  int si = k_xo_options[oi].src;
  uint32_t bit = k_xo_options[oi].bit;
  if (si >= 0) {
    bool v6 = si == XSRC_NOTIFY6 || si == XSRC_XFER6;
    bool is_legacy = zone_level && si == XSRC_NOTIFY4;
    uint8_t st = 0, a[16];
    int fam = AF_UNSPEC;
    char *text = NULL;
    if (read_source_value(ctx, what, key, v6 ? AF_INET6 : AF_INET, &st, a, is_legacy, &fam, is_legacy ? &text : NULL) != 0) return -1;
    conf_token_t tok = get_next_token(ctx);
    if (tok.type != TOKEN_SEMICOLON) {
      if (tok.type == TOKEN_STRING && tok.value && strcmp(tok.value, "port") == 0)
        conf_error(ctx, what, "'%s' takes no port (BIND 9.20 binds the source address with an ephemeral port)", key);
      else
        conf_error(ctx, what, "expected ';' after the address of '%s' but found %s", key, tok_desc(&tok, db, sizeof(db)));
      free_token(&tok);
      free(text);
      return -1;
    }
    free_token(&tok);
    int slot = si;
    if (is_legacy) {
      /* the KariDNS statement is one source for either family; a later one replaces the earlier (and what it set), and notify-source-v6
       * of the same zone wins for IPv6 whichever is written first */
      free(xo->src[XSRC_NOTIFY4].loc);
      memset(&xo->src[XSRC_NOTIFY4], 0, sizeof(xo->src[XSRC_NOTIFY4]));
      if (xo->set & XO_LEGACY_NOTIFY6) {
        free(xo->src[XSRC_NOTIFY6].loc);
        memset(&xo->src[XSRC_NOTIFY6], 0, sizeof(xo->src[XSRC_NOTIFY6]));
        xo->set &= ~XO_LEGACY_NOTIFY6;
      }
      if (fam == AF_INET6) {
        if (xo->src[XSRC_NOTIFY6].state) {
          free(text);
          if (legacy) *legacy = NULL;
          return 0; /* notify-source-v6 is written: the address of the old statement is not the IPv6 source */
        }
        slot = XSRC_NOTIFY6;
        xo->set |= XO_LEGACY_NOTIFY6;
      }
      if (legacy) *legacy = text;
      else free(text);
    } else if (si == XSRC_NOTIFY6) {
      xo->set &= ~XO_LEGACY_NOTIFY6;
    }
    free(xo->src[slot].loc);
    xo->src[slot].state = st;
    memcpy(xo->src[slot].addr, a, 16);
    xo->src[slot].loc = st == 1 ? strdup(loc) : NULL;
    return 0;
  }
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_STRING || !tok.value) {
    conf_error(ctx, what, "expected a value after '%s' but found %s", key, tok_desc(&tok, db, sizeof(db)));
    free_token(&tok);
    return -1;
  }
  if (bit >= XO_B_NOTIFY_TO_SOA && bit <= XO_B_MULTI_MASTER) {
    bool b = false;
    if (!parse_config_bool(tok.value, &b)) {
      conf_error(ctx, what, "invalid %s value '%.64s' (expected yes or no)", key, tok.value);
      free_token(&tok);
      return -1;
    }
    if (b) xo->bools |= bit;
    else xo->bools &= ~bit;
    if (bit == XO_B_TRY_TCP_REFRESH && !b && !ctx->restricted)
      conf_warn_loc(loc, what, "KariDNS checks a secondary zone over TCP only (its IXFR / SOA check); 'try-tcp-refresh no' (UDP first) has no effect");
  } else {
    uint32_t lo = 0, hi = UINT32_MAX;
    const char *range = "0..4294967295";
    if (bit == XO_MIN_REFRESH || bit == XO_MAX_REFRESH || bit == XO_MIN_RETRY || bit == XO_MAX_RETRY) {
      lo = 1;
      range = "1..4294967295 seconds (BIND: must not be zero)";
    } else if (bit >= XO_XFER_TIME_IN && bit <= XO_XFER_IDLE_OUT) {
      hi = XFR_MINUTES_MAX;
      range = "0..40320 minutes (28 days)";
    }
    uint64_t v = 0;
    bool ok = isdigit((unsigned char)tok.value[0]) != 0;
    if (ok) {
      char *end = NULL;
      errno = 0;
      v = strtoull(tok.value, &end, 10);
      ok = errno == 0 && *end == '\0' && v >= lo && v <= hi;
    }
    if (!ok) {
      conf_error(ctx, what, "invalid %s value '%.64s' (expected %s)", key, tok.value, range);
      free_token(&tok);
      return -1;
    }
    switch (bit) {
      case XO_MIN_REFRESH: xo->min_refresh = (uint32_t)v; break;
      case XO_MAX_REFRESH: xo->max_refresh = (uint32_t)v; break;
      case XO_MIN_RETRY: xo->min_retry = (uint32_t)v; break;
      case XO_MAX_RETRY: xo->max_retry = (uint32_t)v; break;
      case XO_XFER_TIME_IN: xo->xfer_time_in = (uint32_t)v; break;
      case XO_XFER_IDLE_IN: xo->xfer_idle_in = (uint32_t)v; break;
      case XO_XFER_TIME_OUT: xo->xfer_time_out = (uint32_t)v; break;
      case XO_XFER_IDLE_OUT: xo->xfer_idle_out = (uint32_t)v; break;
      default: xo->notify_delay = (uint32_t)v; break;
    }
  }
  free_token(&tok);
  xo->set |= bit;
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) {
    conf_error(ctx, what, "expected ';' after the value of '%s' but found %s", key, tok_desc(&tok, db, sizeof(db)));
    free_token(&tok);
    return -1;
  }
  free_token(&tok);
  return 0;
}

/* options { transfers-in; transfers-out; transfers-per-ns; serial-query-rate; notify-rate; startup-notify-rate; }: one unsigned
 * number (BIND: uint32).  1 = taken, 0 = not one of these, -1 = error.  The rates are raised to 1 when 0 (xfr_rate_clamp()). */
static int parse_options_xfr_limit(token_ctx_t *ctx, server_config_t *config, const char *key) {
  struct { const char *name; uint32_t *v; bool *set; } t[] = {
    {"transfers-in", &config->transfers_in, &config->transfers_in_set},
    {"transfers-out", &config->transfers_out, &config->transfers_out_set},
    {"transfers-per-ns", &config->transfers_per_ns, &config->transfers_per_ns_set},
    {"serial-query-rate", &config->serial_query_rate, &config->serial_query_rate_set},
    {"notify-rate", &config->notify_rate, &config->notify_rate_set},
    {"startup-notify-rate", &config->startup_notify_rate, &config->startup_notify_rate_set},
  };
  for (size_t i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
    if (strcmp(t[i].name, key) != 0) continue;
    char what[64], db[96];
    snprintf(what, sizeof(what), "options %s", key);
    conf_token_t tok = get_next_token(ctx);
    uint64_t u = 0;
    bool ok = tok.type == TOKEN_STRING && tok.value && isdigit((unsigned char)tok.value[0]);
    if (ok) {
      char *end = NULL;
      errno = 0;
      u = strtoull(tok.value, &end, 10);
      ok = errno == 0 && *end == '\0' && u <= UINT32_MAX;
    }
    if (!ok) {
      conf_error(ctx, what, "invalid value '%.64s' (expected 0..4294967295)", tok.type == TOKEN_STRING && tok.value ? tok.value : tok_desc(&tok, db, sizeof(db)));
      free_token(&tok);
      return -1;
    }
    free_token(&tok);
    tok = get_next_token(ctx);
    if (tok.type != TOKEN_SEMICOLON) {
      conf_error(ctx, what, "expected ';' after the value but found %s", tok_desc(&tok, db, sizeof(db)));
      free_token(&tok);
      return -1;
    }
    free_token(&tok);
    *t[i].v = (uint32_t)u;
    *t[i].set = true;
    return 1;
  }
  return 0;
}

uint32_t xfr_cfg_limit(const server_config_t *cfg, int which) {
  switch (which) {
    case XL_TRANSFERS_IN: return cfg && cfg->transfers_in_set ? cfg->transfers_in : XFR_TRANSFERS_IN_DEFAULT;
    case XL_TRANSFERS_OUT: return cfg && cfg->transfers_out_set ? cfg->transfers_out : XFR_TRANSFERS_OUT_DEFAULT;
    case XL_TRANSFERS_PER_NS: return cfg && cfg->transfers_per_ns_set ? cfg->transfers_per_ns : XFR_TRANSFERS_PER_NS_DEFAULT;
    case XL_SERIAL_QUERY_RATE: return xfr_rate_clamp(cfg && cfg->serial_query_rate_set ? cfg->serial_query_rate : XFR_RATE_DEFAULT);
    case XL_NOTIFY_RATE: return xfr_rate_clamp(cfg && cfg->notify_rate_set ? cfg->notify_rate : XFR_RATE_DEFAULT);
    default: return xfr_rate_clamp(cfg && cfg->startup_notify_rate_set ? cfg->startup_notify_rate : XFR_RATE_DEFAULT);
  }
}

uint32_t xfr_rate_clamp(uint32_t v) { return v == 0 ? 1 : v; }

uint32_t xfr_minutes_to_secs(uint32_t minutes) {
  uint32_t unit = 60;
  const char *e = getenv("KARIDNS_XFER_MINUTE_SECS");
  if (e && *e) {
    char *end = NULL;
    long v = strtol(e, &end, 10);
    if (*end == '\0' && v >= 1 && v <= 60) unit = (uint32_t)v;
  }
  return minutes * unit; /* minutes <= 40320: no overflow */
}

uint32_t xfr_range(uint32_t a, uint32_t lo, uint32_t hi) { return a < lo ? lo : (a < hi ? a : hi); }

void xfr_clamp_timers(const xfr_eff_t *e, uint32_t soa_refresh, uint32_t soa_retry, uint32_t soa_expire, uint32_t *refresh,
                      uint32_t *retry, uint32_t *expire) {
  uint32_t r = xfr_range(soa_refresh, e->min_refresh, e->max_refresh);
  uint32_t t = xfr_range(soa_retry, e->min_retry, e->max_retry);
  uint64_t floor_expire = (uint64_t)r + t;
  uint32_t x = xfr_range(soa_expire, floor_expire > UINT32_MAX ? UINT32_MAX : (uint32_t)floor_expire, XFR_MAX_EXPIRE);
  if (refresh) *refresh = r;
  if (retry) *retry = t;
  if (expire) *expire = x;
}

static const xfr_opts_t *xo_of_view(const server_config_t *cfg, const char *view_name) {
  if (!cfg || !view_name || !view_name[0]) return NULL;
  for (const view_config_t *v = cfg->views; v; v = v->next)
    if (strcasecmp(v->name, view_name) == 0) return &v->xo;
  return NULL;
}

void zone_limits_effective(const server_config_t *cfg, const zone_config_t *zone, const char *view_name, zone_limits_t *out) {
  zone_veff_t v;
  zone_vopts_effective(cfg, zone, view_name, &v);
  out->max_records = v.max_records;
  out->max_per_type = v.max_per_type;
  out->max_types_per_name = v.max_types_per_name;
  /* BIND: max-zone-ttl is a primary zone's option (zone_clauses: CFG_ZONE_PRIMARY) */
  const char *type = zone && zone->type ? zone->type : "primary";
  out->max_zone_ttl = (strcasecmp(type, "primary") == 0 || strcasecmp(type, "master") == 0) ? v.max_zone_ttl : 0;
}

void xfr_opts_effective(const server_config_t *cfg, const zone_config_t *zone, const char *view_name, xfr_eff_t *out) {
  xfr_opts_effective_peer(cfg, zone, view_name, NULL, out);
}

void xfr_opts_effective_peer(const server_config_t *cfg, const zone_config_t *zone, const char *view_name, const server_stmt_t *srv, xfr_eff_t *out) {
  memset(out, 0, sizeof(*out));
  out->min_refresh = XFR_MIN_REFRESH_DEFAULT;
  out->max_refresh = XFR_MAX_REFRESH_DEFAULT;
  out->min_retry = XFR_MIN_RETRY_DEFAULT;
  out->max_retry = XFR_MAX_RETRY_DEFAULT;
  out->xfer_time_in = xfr_minutes_to_secs(XFR_TIME_IN_DEFAULT);
  out->xfer_idle_in = xfr_minutes_to_secs(XFR_IDLE_IN_DEFAULT);
  out->xfer_time_out = xfr_minutes_to_secs(XFR_TIME_OUT_DEFAULT);
  out->xfer_idle_out = xfr_minutes_to_secs(XFR_IDLE_OUT_DEFAULT);
  out->notify_delay = XFR_NOTIFY_DELAY_DEFAULT;
  out->try_tcp_refresh = out->request_ixfr = out->provide_ixfr = out->request_expire = true;
  /* the first level that wrote an option decides it: the server statement of the peer (request-ixfr, provide-ixfr, request-expire:
   * BIND zone.c / xfrout.c use the peer's value when it is set), then zone, view, options */
  const xfr_opts_t *lv[4] = { srv ? &srv->xo : NULL, zone ? zext(zone)->xo : NULL, xo_of_view(cfg, view_name), cfg ? &cfg->xo : NULL };
  uint32_t done = 0;   /* the options a higher level has decided already */
  for (int i = 0; i < 4; i++) {
    const xfr_opts_t *l = lv[i];
    if (!l) continue;
    uint32_t w = l->set & ~done;
    if (w & XO_MIN_REFRESH) out->min_refresh = l->min_refresh;
    if (w & XO_MAX_REFRESH) out->max_refresh = l->max_refresh;
    if (w & XO_MIN_RETRY) out->min_retry = l->min_retry;
    if (w & XO_MAX_RETRY) out->max_retry = l->max_retry;
    if (w & XO_XFER_TIME_IN) out->xfer_time_in = xfr_minutes_to_secs(l->xfer_time_in);
    if (w & XO_XFER_IDLE_IN) out->xfer_idle_in = xfr_minutes_to_secs(l->xfer_idle_in);
    if (w & XO_XFER_TIME_OUT) out->xfer_time_out = xfr_minutes_to_secs(l->xfer_time_out);
    if (w & XO_XFER_IDLE_OUT) out->xfer_idle_out = xfr_minutes_to_secs(l->xfer_idle_out);
    if (w & XO_NOTIFY_DELAY) out->notify_delay = l->notify_delay;
    if (w & XO_B_NOTIFY_TO_SOA) out->notify_to_soa = (l->bools & XO_B_NOTIFY_TO_SOA) != 0;
    if (w & XO_B_TRY_TCP_REFRESH) out->try_tcp_refresh = (l->bools & XO_B_TRY_TCP_REFRESH) != 0;
    if (w & XO_B_REQUEST_IXFR) out->request_ixfr = (l->bools & XO_B_REQUEST_IXFR) != 0;
    if (w & XO_B_PROVIDE_IXFR) out->provide_ixfr = (l->bools & XO_B_PROVIDE_IXFR) != 0;
    if (w & XO_B_REQUEST_EXPIRE) out->request_expire = (l->bools & XO_B_REQUEST_EXPIRE) != 0;
    if (w & XO_B_MULTI_MASTER) out->multi_master = (l->bools & XO_B_MULTI_MASTER) != 0;
    done |= l->set;
  }
  /* sources: per statement (notify-source, notify-source-v6, transfer-source, transfer-source-v6), the first level that wrote it */
  for (int s = 0; s < XSRC_N; s++) {
    if (srv && srv->xo.src[s].state) {   /* the peer's own source (BIND: transfer-source / notify-source of the server beats the list's `source`) */
      out->psrc[s].state = srv->xo.src[s].state;
      memcpy(out->psrc[s].addr, srv->xo.src[s].addr, 16);
    }
    for (int i = 1; i < 4; i++) {
      const xfr_opts_t *l = lv[i];
      if (!l || !l->src[s].state) continue;
      if (l->src[s].state == 1) {
        out->src[s].set = true;
        memcpy(out->src[s].addr, l->src[s].addr, 16);
      }
      break; /* `*` (state 2) also ends the search: the system chooses */
    }
  }
}

bool xfr_source_for(const xfr_eff_t *e, const notify_target_t *t, int family, bool xfer, uint8_t out[16]) {
  int idx = family == AF_INET6 ? 1 : 0;
  int slot = xfer ? (idx ? XSRC_XFER6 : XSRC_XFER4) : (idx ? XSRC_NOTIFY6 : XSRC_NOTIFY4);
  /* BIND zone.c soa_query() / notify_send_toaddr(): the source of the server statement first (`*` too: the system chooses), then the
   * `source` of the list the address is written in, then the zone's / view's / options' transfer-source or notify-source */
  if (e && e->psrc[slot].state) {
    if (e->psrc[slot].state != 1) return false;
    memcpy(out, e->psrc[slot].addr, 16);
    return true;
  }
  if (t && t->src_set[idx]) {
    memcpy(out, t->src[idx], 16);
    return true;
  }
  if (e && e->src[slot].set) {
    memcpy(out, e->src[slot].addr, 16);
    return true;
  }
  return false;
}

/* ---- Batch 5: server <prefix> { ... }; (BIND 9.20 ARM "server Statement Definition and Usage"; lib/isccfg/namedconf.c server_clauses and
 * cfg_parse_netprefix_map(); the checks of lib/isccfg/check.c check_servers(); the values of bin/named/server.c configure_peer()) ---- */

enum { SVK_BOOL = 0, SVK_UINT, SVK_KEYS, SVK_FORMAT, SVK_XO, SVK_IGNORED_SOURCE, SVK_ANCIENT };
static const struct { const char *name; uint32_t bit; int kind; } k_sv_options[] = {
  {"bogus", SV_B_BOGUS, SVK_BOOL}, {"edns", SV_B_EDNS, SVK_BOOL}, {"request-nsid", SV_B_REQUEST_NSID, SVK_BOOL},
  {"send-cookie", SV_B_SEND_COOKIE, SVK_BOOL}, {"require-cookie", SV_B_REQUIRE_COOKIE, SVK_BOOL},
  {"tcp-keepalive", SV_B_TCP_KEEPALIVE, SVK_BOOL}, {"tcp-only", SV_B_TCP_ONLY, SVK_BOOL},
  {"edns-udp-size", SV_EDNS_UDP_SIZE, SVK_UINT}, {"edns-version", SV_EDNS_VERSION, SVK_UINT}, {"max-udp-size", SV_MAX_UDP_SIZE, SVK_UINT},
  {"padding", SV_PADDING, SVK_UINT}, {"transfers", SV_TRANSFERS, SVK_UINT},
  {"keys", SV_KEYS, SVK_KEYS}, {"transfer-format", SV_TRANSFER_FORMAT, SVK_FORMAT},
  {"request-ixfr", 0, SVK_XO}, {"provide-ixfr", 0, SVK_XO}, {"request-expire", 0, SVK_XO}, {"notify-source", 0, SVK_XO},
  {"notify-source-v6", 0, SVK_XO}, {"transfer-source", 0, SVK_XO}, {"transfer-source-v6", 0, SVK_XO},
  {"query-source", 0, SVK_IGNORED_SOURCE}, {"query-source-v6", 0, SVK_IGNORED_SOURCE},
  {"request-sit", 0, SVK_ANCIENT}, {"support-ixfr", 0, SVK_ANCIENT},
};

/* the prefix of a server statement as text ("192.0.2.0/24"; a single address without the length) */
static void server_prefix_text(const server_stmt_t *s, char *buf, size_t n) {
  char ip[INET6_ADDRSTRLEN] = "?";
  inet_ntop(s->family, s->addr, ip, sizeof(ip));
  if (s->plen == (s->family == AF_INET ? 32 : 128)) snprintf(buf, n, "%s", ip);
  else snprintf(buf, n, "%s/%u", ip, (unsigned)s->plen);
}

/* "<address>[/<length>]" into s->family / plen / addr.  false = not a prefix, or bits beyond the length are set (BIND check_servers():
 * "invalid prefix (extra bits specified)"); *why says which. */
static bool server_prefix_parse(const char *text, server_stmt_t *s, const char **why) {
  char buf[96];
  if (strlen(text) >= sizeof(buf)) { *why = "is not an address or prefix"; return false; }
  snprintf(buf, sizeof(buf), "%s", text);
  char *slash = strchr(buf, '/');
  long plen = -1;
  if (slash) {
    *slash++ = '\0';
    char *end = NULL;
    if (!isdigit((unsigned char)*slash)) { *why = "has no valid prefix length"; return false; }
    plen = strtol(slash, &end, 10);
    if (*end != '\0') { *why = "has no valid prefix length"; return false; }
  }
  memset(s->addr, 0, sizeof(s->addr));
  if (inet_pton(AF_INET, buf, s->addr) == 1) s->family = AF_INET;
  else if (inet_pton(AF_INET6, buf, s->addr) == 1) s->family = AF_INET6;
  else { *why = "is not an address or prefix"; return false; }
  long max = s->family == AF_INET ? 32 : 128;
  if (plen < 0) plen = max;
  if (plen > max) { *why = "has a prefix length that is too long"; return false; }
  s->plen = (uint8_t)plen;
  for (long b = plen; b < max; b++)
    if (s->addr[b / 8] & (0x80 >> (b % 8))) { *why = "is an invalid prefix (extra bits specified)"; return false; }
  return true;
}

static bool server_prefix_covers(const server_stmt_t *s, int family, const uint8_t *addr) {
  if (s->family != family) return false;
  unsigned full = s->plen / 8, rest = s->plen % 8;
  if (full && memcmp(s->addr, addr, full) != 0) return false;
  if (rest && ((s->addr[full] ^ addr[full]) & (0xFF << (8 - rest)) & 0xFF) != 0) return false;
  return true;
}

const server_stmt_t *server_list_find(const server_stmt_t *list, int family, const uint8_t *addr) {
  if (!addr) return NULL;
  for (const server_stmt_t *s = list; s; s = s->next)
    if (server_prefix_covers(s, family, addr)) return s;
  return NULL;
}

const server_stmt_t *config_server_find(const server_config_t *cfg, const char *view_name, int family, const uint8_t *addr) {
  if (!cfg || !addr) return NULL;
  const server_stmt_t *list = cfg->servers;
  if (view_name && view_name[0])
    for (const view_config_t *v = cfg->views; v; v = v->next)
      if (strcasecmp(v->name, view_name) == 0) {
        if (v->servers) list = v->servers;
        break;
      }
  return server_list_find(list, family, addr);
}

const server_stmt_t *config_server_find_ip(const server_config_t *cfg, const char *view_name, const char *ip) {
  uint8_t a[16];
  if (!ip) return NULL;
  if (inet_pton(AF_INET, ip, a) == 1) return config_server_find(cfg, view_name, AF_INET, a);
  if (inet_pton(AF_INET6, ip, a) == 1) return config_server_find(cfg, view_name, AF_INET6, a);
  return NULL;
}

const server_stmt_t *config_server_find_sa(const server_config_t *cfg, const char *view_name, const struct sockaddr *sa) {
  if (!sa) return NULL;
  if (sa->sa_family == AF_INET) return config_server_find(cfg, view_name, AF_INET, (const uint8_t *)&((const struct sockaddr_in *)sa)->sin_addr);
  if (sa->sa_family != AF_INET6) return NULL;
  const struct in6_addr *a6 = &((const struct sockaddr_in6 *)sa)->sin6_addr;
  if (IN6_IS_ADDR_V4MAPPED(a6)) return config_server_find(cfg, view_name, AF_INET, &a6->s6_addr[12]);
  return config_server_find(cfg, view_name, AF_INET6, a6->s6_addr);
}

const char *peer_key_name(const char *element_key, const server_stmt_t *srv, const char *zone_key) {
  if (element_key && element_key[0]) return element_key;
  if (srv && (srv->set & SV_KEYS) && srv->key && srv->key[0]) return srv->key;
  return zone_key && zone_key[0] ? zone_key : NULL;
}

/* value of an unsigned option (BIND cfg_type_uint32) */
static int server_read_uint(token_ctx_t *ctx, const char *what, const char *key, uint32_t *out) {
  char db[96];
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_STRING || !tok.value) {
    conf_error(ctx, what, "expected a number after '%s' but found %s", key, tok_desc(&tok, db, sizeof(db)));
    free_token(&tok);
    return -1;
  }
  bool ok = isdigit((unsigned char)tok.value[0]) != 0;
  unsigned long long v = 0;
  if (ok) {
    char *end = NULL;
    errno = 0;
    v = strtoull(tok.value, &end, 10);
    ok = errno == 0 && *end == '\0' && v <= UINT32_MAX;
  }
  if (!ok) conf_error(ctx, what, "invalid %s value '%.64s' (expected 0..4294967295)", key, tok.value);
  free_token(&tok);
  if (!ok) return -1;
  *out = (uint32_t)v;
  return 0;
}

/* After a value the statement ends with ';' */
static int server_expect_semicolon(token_ctx_t *ctx, const char *what, const char *key) {
  char db[96];
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) {
    conf_error(ctx, what, "expected ';' after the value of '%s' but found %s", key, tok_desc(&tok, db, sizeof(db)));
    free_token(&tok);
    return -1;
  }
  free_token(&tok);
  return 0;
}

/* keys <name>;  keys { <name>; };  keys { <name> };  (BIND parse_server_key_kludge(): one key, with or without braces).  The name goes to *out. */
static int server_read_keys(token_ctx_t *ctx, const char *what, char **out) {
  char db[96];
  bool braces = false;
  conf_token_t tok = get_next_token(ctx);
  if (tok.type == TOKEN_LBRACE) {
    braces = true;
    free_token(&tok);
    tok = get_next_token(ctx);
  }
  if (tok.type != TOKEN_STRING || !tok.value) {
    conf_error(ctx, what, "expected a key name after 'keys' but found %s", tok_desc(&tok, db, sizeof(db)));
    free_token(&tok);
    return -1;
  }
  *out = tok.value;
  tok.value = NULL;
  free_token(&tok);
  if (braces) {
    tok = get_next_token(ctx);
    if (tok.type == TOKEN_SEMICOLON) {
      free_token(&tok);
      tok = get_next_token(ctx);
    }
    if (tok.type != TOKEN_RBRACE) {
      conf_error(ctx, what, "'keys' takes one key name (expected '}' but found %s)", tok_desc(&tok, db, sizeof(db)));
      free_token(&tok);
      free(*out);
      *out = NULL;
      return -1;
    }
    free_token(&tok);
  }
  return 0;
}

/* server <prefix> { ... }; after the word `server` has been read.  The statement is added to *list (most specific prefix first, a later one
 * of the same length after the earlier ones: BIND dns_peerlist_addpeer()).  scope is "" at the top level and "view 'x' " in a view. */
static int parse_server_block(token_ctx_t *ctx, server_stmt_t **list, const char *scope) {
  char db[96], loc[300], what[200];
  ctx_location(ctx, loc, sizeof(loc));
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_STRING || !tok.value) {
    conf_error(ctx, "server", "expected an address or prefix but found %s", tok_desc(&tok, db, sizeof(db)));
    free_token(&tok);
    return -1;
  }
  server_stmt_t *s = calloc(1, sizeof(*s));
  if (!s) { free_token(&tok); if (ctx) ctx->error_occurred = true; return -1; }
  snprintf(s->loc, sizeof(s->loc), "%s", loc);
  const char *why = NULL;
  snprintf(what, sizeof(what), "%sserver '%.64s'", scope, tok.value);
  if (!server_prefix_parse(tok.value, s, &why)) {
    conf_error(ctx, what, "'%.64s' %s", tok.value, why);
    free_token(&tok);
    free(s);
    return -1;
  }
  free_token(&tok);
  {
    char pt[96];
    server_prefix_text(s, pt, sizeof(pt));
    snprintf(what, sizeof(what), "%sserver '%s'", scope, pt);
  }
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_LBRACE) {
    conf_error(ctx, what, "expected '{' but found %s", tok_desc(&tok, db, sizeof(db)));
    free_token(&tok);
    goto fail;
  }
  free_token(&tok);
  const char *seen[sizeof(k_sv_options) / sizeof(k_sv_options[0])];
  size_t nseen = 0;
  for (;;) {
    tok = get_next_token(ctx);
    if (tok.type == TOKEN_RBRACE) {
      free_token(&tok);
      break;
    }
    if (tok.type != TOKEN_STRING || !tok.value) {
      conf_error(ctx, what, "expected an option name but found %s%s", tok_desc(&tok, db, sizeof(db)),
                 tok.type == TOKEN_EOF ? " (missing '}')" : "");
      free_token(&tok);
      goto fail;
    }
    size_t oi = 0;
    while (oi < sizeof(k_sv_options) / sizeof(k_sv_options[0]) && strcmp(k_sv_options[oi].name, tok.value) != 0) oi++;
    if (oi == sizeof(k_sv_options) / sizeof(k_sv_options[0])) {
      conf_error(ctx, what, "unknown option '%.64s' (check the spelling; the options of a server statement are listed in the BIND 9.20 ARM)", tok.value);
      free_token(&tok);
      goto fail;
    }
    free_token(&tok);
    const char *key = k_sv_options[oi].name;
    uint32_t bit = k_sv_options[oi].bit;
    char owhat[260];
    snprintf(owhat, sizeof(owhat), "%s: %s", what, key);
    for (size_t i = 0; i < nseen; i++)
      if (strcmp(seen[i], key) == 0) {
        conf_error(ctx, what, "duplicate '%s' option", key);
        goto fail;
      }
    seen[nseen++] = key;
    char oloc[300];
    ctx_location(ctx, oloc, sizeof(oloc));
    switch (k_sv_options[oi].kind) {
      case SVK_ANCIENT:
        conf_error(ctx, what, "option '%s' no longer exists", key);
        goto fail;
      case SVK_XO:
        if (parse_xfr_option(ctx, what, key, &s->xo, false, NULL) != 0) goto fail;
        break;
      case SVK_KEYS:
        if (server_read_keys(ctx, what, &s->key) != 0 || server_expect_semicolon(ctx, what, key) != 0) goto fail;
        s->set |= SV_KEYS;
        break;
      case SVK_FORMAT: {
        tok = get_next_token(ctx);
        bool one = tok.type == TOKEN_STRING && tok.value && strcasecmp(tok.value, "one-answer") == 0;
        bool many = tok.type == TOKEN_STRING && tok.value && strcasecmp(tok.value, "many-answers") == 0;
        if (!one && !many) {
          conf_error(ctx, what, "invalid transfer-format value %s (expected one-answer or many-answers)", tok_desc(&tok, db, sizeof(db)));
          free_token(&tok);
          goto fail;
        }
        free_token(&tok);
        if (server_expect_semicolon(ctx, what, key) != 0) goto fail;
        s->set |= SV_TRANSFER_FORMAT;
        if (one) s->bools |= SV_B_ONE_ANSWER;
        break;
      }
      case SVK_BOOL: {
        tok = get_next_token(ctx);
        bool b = false;
        if (tok.type != TOKEN_STRING || !tok.value || !parse_config_bool(tok.value, &b)) {
          conf_error(ctx, what, "invalid %s value %s (expected yes or no)", key, tok_desc(&tok, db, sizeof(db)));
          free_token(&tok);
          goto fail;
        }
        free_token(&tok);
        if (server_expect_semicolon(ctx, what, key) != 0) goto fail;
        s->set |= bit;
        if (b) s->bools |= bit;
        else s->bools &= ~bit;
        break;
      }
      case SVK_UINT: {
        uint32_t v = 0;
        if (server_read_uint(ctx, what, key, &v) != 0 || server_expect_semicolon(ctx, what, key) != 0) goto fail;
        s->set |= bit;
        /* bin/named/server.c configure_peer(): the values are brought into range, not refused */
        switch (bit) {
          case SV_EDNS_UDP_SIZE: s->edns_udp_size = v < 512 ? 512 : (v > 4096 ? 4096 : v); break;
          case SV_MAX_UDP_SIZE: s->max_udp_size = v < 512 ? 512 : (v > 4096 ? 4096 : v); break;
          case SV_EDNS_VERSION: s->edns_version = v > 255 ? 255 : v; break;
          case SV_PADDING:
            if (v > 512) {
              conf_warn_loc(oloc, what, "padding cannot exceed 512: lowered to 512");
              v = 512;
            }
            s->padding = v;
            break;
          default: s->transfers = v; break;
        }
        break;
      }
      default: {   /* query-source, query-source-v6: read to the ';' */
        int n = 0;
        for (;;) {
          tok = get_next_token(ctx);
          if (tok.type == TOKEN_SEMICOLON) { free_token(&tok); break; }
          if (tok.type != TOKEN_STRING || !tok.value) {
            conf_error(ctx, what, "expected an address after '%s' but found %s", key, tok_desc(&tok, db, sizeof(db)));
            free_token(&tok);
            goto fail;
          }
          n++;
          free_token(&tok);
        }
        if (n == 0) {
          conf_error(ctx, what, "expected an address after '%s'", key);
          goto fail;
        }
        break;
      }
    }
    /* options that BIND uses only for its resolver, DS checks or encrypted transports: valid, and nothing for an authoritative server to do */
    switch (k_sv_options[oi].kind == SVK_IGNORED_SOURCE ? 1000 : (int)bit) {
      case SV_B_BOGUS:
        conf_warn_loc(oloc, what, "bogus is accepted, no effect in KariDNS (BIND uses it to stop its resolver from querying a server)");
        break;
      case SV_B_SEND_COOKIE: case SV_B_REQUIRE_COOKIE:
        conf_warn_loc(oloc, what, "%s is accepted, no effect in KariDNS (it sends no DNS COOKIE in its SOA, transfer and NOTIFY requests)", key);
        break;
      case SV_B_TCP_KEEPALIVE: case SV_PADDING:
        conf_warn_loc(oloc, what, "%s is accepted, no effect in KariDNS (BIND uses it for the queries of its resolver)", key);
        break;
      case 1000:
        conf_warn_loc(oloc, what, "%s is accepted, no effect in KariDNS (BIND uses it for the DS checks of parental-agents)", key);
        break;
      default: break;
    }
  }
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) {
    conf_error(ctx, what, "expected ';' after '}' but found %s", tok_desc(&tok, db, sizeof(db)));
    free_token(&tok);
    goto fail;
  }
  free_token(&tok);
  /* check_servers(): a request to an IPv4 server leaves from an IPv4 address and one to an IPv6 server from an IPv6 address */
  {
    int bad = s->family == AF_INET ? (s->xo.src[XSRC_NOTIFY6].state ? XSRC_NOTIFY6 : (s->xo.src[XSRC_XFER6].state ? XSRC_XFER6 : -1))
                                   : (s->xo.src[XSRC_NOTIFY4].state ? XSRC_NOTIFY4 : (s->xo.src[XSRC_XFER4].state ? XSRC_XFER4 : -1));
    if (bad >= 0) {
      conf_error(ctx, what, "%s is not legal for %s server", bad == XSRC_NOTIFY6 ? "notify-source-v6" : bad == XSRC_XFER6 ? "transfer-source-v6"
                 : bad == XSRC_NOTIFY4 ? "notify-source" : "transfer-source", s->family == AF_INET ? "an IPv4" : "an IPv6");
      goto fail;
    }
  }
  for (const server_stmt_t *e = *list; e; e = e->next)
    if (e->family == s->family && e->plen == s->plen && memcmp(e->addr, s->addr, 16) == 0) {
      conf_error(ctx, what, "already exists, previous definition: %s", e->loc);
      goto fail;
    }
  server_stmt_t **pp = list;
  while (*pp && (*pp)->plen >= s->plen) pp = &(*pp)->next;
  s->next = *pp;
  *pp = s;
  return 0;
fail:
  server_stmts_free(s);
  if (ctx) ctx->error_occurred = true;
  return -1;
}

/* After the parse: the key of every server statement must be defined where the statement applies.  A view's own statements replace the
 * top-level ones, so each view checks the list it uses against the global keys and its own (check_servers(): "unknown key"). */
static int servers_check_keys(token_ctx_t *ctx, server_config_t *cfg) {
  cfg->any_server_max_udp = false;
  for (const server_stmt_t *s = cfg->servers; s; s = s->next)
    if (s->set & SV_MAX_UDP_SIZE) cfg->any_server_max_udp = true;
  for (const view_config_t *v = cfg->views; v; v = v->next)
    for (const server_stmt_t *s = v->servers; s; s = s->next)
      if (s->set & SV_MAX_UDP_SIZE) cfg->any_server_max_udp = true;
  for (const view_config_t *v = cfg->views; v; v = v->next) {
    const server_stmt_t *list = v->servers ? v->servers : cfg->servers;
    ctx->scope_keys = v->keys;
    for (const server_stmt_t *s = list; s; s = s->next) {
      if (!(s->set & SV_KEYS) || key_is_defined(ctx, cfg, s->key)) continue;
      char pt[96];
      server_prefix_text(s, pt, sizeof(pt));
      bool dflt = strcmp(v->name, "__default__") == 0;
      syslog(LOG_ERR, "[Config] %s: server '%s': unknown key '%.64s'%s%s%s", s->loc, pt, s->key, dflt ? "" : " (in view '", dflt ? "" : v->name, dflt ? "" : "')");
      fprintf(stderr, "[ERROR] %s: server '%s': unknown key '%.64s'%s%s%s\n", s->loc, pt, s->key, dflt ? "" : " (in view '", dflt ? "" : v->name, dflt ? "" : "')");
      ctx->scope_keys = NULL;
      ctx->error_occurred = true;
      return -1;
    }
  }
  ctx->scope_keys = NULL;
  /* a key of a view must not have the name of a global key (check_keylist(): the view is checked together with the global keys) */
  for (const view_config_t *v = cfg->views; v; v = v->next)
    for (const tsig_key_t *k = v->keys; k; k = k->next)
      if (key_name_is_defined(cfg->keys, k->name)) {
        syslog(LOG_ERR, "[Config] view '%s': key '%s' already exists as a top-level key; the name of a key in a view must be new", v->name, k->name);
        fprintf(stderr, "[ERROR] view '%s': key '%s' already exists as a top-level key; the name of a key in a view must be new\n", v->name, k->name);
        ctx->error_occurred = true;
        return -1;
      }
  return 0;
}

/* B6a (open item 2, decided 2026-10-21): an unknown statement inside zone { } or view { } used to be skipped without a
 * word, so a typo ("alow-transfer") silently left a zone open or closed.  Now:
 *   - an option BIND 9 documents for a zone / view statement but KariDNS does not implement is skipped with a warning;
 *   - anything else is a configuration error, shown by karidns and by `karicheck conf`.
 * The lists are the zone and view options of the BIND 9.18 / 9.20 ARM ("zone Statement Grammar", "view Statement
 * Grammar") minus what KariDNS reads; options of options { } that a view may also carry are on the view list.  Only
 * zone { }, view { } and control-channel { } are strict; key { }, logging { } and options { } keep skipping unknowns. */
static const char *const k_bind_zone_options[] = {
  "allow-notify", "allow-query", "allow-query-on", "allow-update-forwarding", "auto-dnssec", "check-dup-records",
  "check-integrity", "check-mx", "check-mx-cname", "check-names", "check-sibling", "check-spf", "check-srv-cname",
  "check-wildcard", "database", "delegation-only", "dialup", "dlz", "dnssec-dnskey-kskonly", "dnssec-loadkeys-interval",
  "dnssec-policy", "dnssec-secure-to-insecure", "dnssec-update-mode", "forward", "in-view", "inline-signing",
  "ixfr-from-differences", "journal", "key-directory", "masterfile-format", "masterfile-style", "max-ixfr-ratio",
  "max-journal-size", "max-records", "max-refresh-time", "max-retry-time", "max-transfer-idle-in", "max-transfer-idle-out",
  "max-transfer-time-in", "max-transfer-time-out", "max-zone-ttl", "min-refresh-time", "min-retry-time", "min-transfer-rate-in", "multi-master",
  "notify-delay", "notify-source-v6", "notify-to-soa", "nta-lifetime", "nta-recheck", "parental-agents",
  "parental-source", "parental-source-v6", "request-expire", "request-ixfr", "request-nsid",
  "require-server-cookie", "send-report-channel", "serial-update-method", "server-addresses", "server-names",
  "sig-signing-nodes", "sig-signing-signatures", "sig-signing-type", "sig-validity-interval", "transfer-source",
  "transfer-source-v6", "try-tcp-refresh", "update-check-ksk", "update-policy", "use-alt-transfer-source",
  "zero-no-soa-ttl", "zone-statistics", NULL
};

static const char *const k_bind_view_options[] = {
  "allow-notify", "allow-query", "allow-query-cache", "allow-query-cache-on", "allow-query-on", "allow-recursion",
  "allow-recursion-on", "allow-transfer", "allow-update", "allow-update-forwarding", "also-notify", "attach-cache",
  "auto-dnssec", "cache-file", "check-dup-records", "check-integrity", "check-mx", "check-mx-cname", "check-names",
  "check-sibling", "check-spf", "check-srv-cname", "check-wildcard", "clients-per-query", "deny-answer-addresses",
  "deny-answer-aliases", "disable-algorithms", "disable-ds-digests", "disable-empty-zone", "dns64", "dns64-contact",
  "dns64-server", "dnssec-accept-expired", "dnssec-enable", "dnssec-lookaside", "dnssec-must-be-secure",
  "dnssec-policy", "dnssec-validation", "dnstap", "dual-stack-servers", "edns-udp-size", "empty-contact", "empty-server",
  "empty-zones-enable", "fetch-quota-params", "fetches-per-server", "fetches-per-zone", "forward", "forwarders",
  "glue-cache", "inline-signing", "ixfr-from-differences", "key", "key-directory", "lame-ttl", "lmdb-mapsize",
  "managed-keys", "match-destinations", "match-recursive-only", "max-cache-size", "max-cache-ttl", "max-clients-per-query",
  "max-ixfr-ratio", "max-journal-size", "max-ncache-ttl", "max-records", "max-recursion-depth", "max-recursion-queries",
  "max-refresh-time", "max-retry-time", "max-stale-ttl", "max-udp-size", "max-zone-ttl", "message-compression",
  "min-cache-ttl", "min-ncache-ttl", "min-refresh-time", "min-retry-time", "min-transfer-rate-in", "minimal-any", "minimal-responses",
  "notify-delay", "notify-source", "notify-source-v6", "notify-to-soa", "nocookie-udp-size", "nosit-udp-size",
  "nta-lifetime", "nta-recheck", "nxdomain-redirect", "parental-source", "parental-source-v6", "preferred-glue",
  "prefetch", "provide-ixfr", "qname-minimization", "query-source", "query-source-v6", "rate-limit", "recursion",
  "request-expire", "request-ixfr", "request-nsid", "require-server-cookie", "resolver-nonbackoff-tries",
  "resolver-query-timeout", "resolver-retry-interval", "response-padding", "response-policy", "root-delegation-only",
  "rrset-order", "send-cookie", "serial-update-method", "servfail-ttl", "sig-signing-nodes", "sig-signing-signatures",
  "sig-signing-type", "sig-validity-interval", "sortlist", "stale-answer-client-timeout", "stale-answer-enable",
  "stale-answer-ttl", "stale-cache-enable", "stale-refresh-time", "synth-from-dnssec", "transfer-format",
  "transfer-source", "transfer-source-v6", "trust-anchor-telemetry", "trust-anchors", "trusted-keys", "try-tcp-refresh",
  "update-check-ksk", "v6-bias", "validate-except", "zero-no-soa-ttl", "zone-statistics", NULL
};

static bool name_in_list(const char *const *list, const char *key) {
  for (size_t i = 0; list[i]; i++)
    if (strcmp(list[i], key) == 0) return true;
  return false;
}

/* The statement `key` (already read) inside zone / view `what` is not one KariDNS implements.  Skips the statement and
 * returns 0 when BIND documents it (warning), or reports a configuration error and returns -1 (the caller frees its
 * partial result and returns -1). */
static int unknown_statement(token_ctx_t *ctx, const char *kind, const char *name, const char *key, bool in_view) {
  if (name_in_list(in_view ? k_bind_view_options : k_bind_zone_options, key)) {
    syslog(LOG_WARNING, "[Config] %s '%s': option '%s' is a BIND option that KariDNS does not implement; it is ignored", kind,
           name, key);
    fprintf(stderr, "[WARNING] %s '%s': option '%s' is a BIND option that KariDNS does not implement; it is ignored\n", kind,
            name, key);
    skip_unknown_block(ctx);
    return 0;
  }
  syslog(LOG_ERR, "[Config] %s '%s': unknown option '%.64s' (neither a KariDNS option nor a BIND option for this statement; check the spelling)", kind, name,
         key);
  fprintf(stderr, "[ERROR] %s '%s': unknown option '%.64s' (neither a KariDNS option nor a BIND option for this statement; check the spelling)\n", kind,
          name, key);
  if (ctx) ctx->error_occurred = true;
  return -1;
}

/* Strict options { } and key { } (decided 2026-10-28; zone { } and view { } have been strict since B6a).  A misspelt
 * `bind-address`, `user`, `listen-on` or `secret` used to be skipped without a word and had no effect.  Now a statement
 * that BIND documents for the block but KariDNS does not implement is skipped with a warning, and anything else is a
 * configuration error with file:line.
 * k_bind_options_options: the union of the "options Statement Grammar" of the BIND 9.18.28 ARM and of the 9.20.0 ARM
 * (fetched from bind9.readthedocs.io; 9.20 added allow-proxy, allow-proxy-on, check-svcb, dnsrps-library,
 * max-validation-failures-per-fetch, max-validations-per-fetch, resolver-use-dns64, sig0checks-quota[-exempt];
 * 9.18-only ones kept: alt-transfer-source[-v6], auto-dnssec, coresize, datasize, dscp, files, glue-cache, lock-file,
 * random-device, reserved-sockets, resolver-nonbackoff-tries, resolver-retry-interval, root-delegation-only,
 * stacksize, suppress-initial-notify, tkey-dhkey, use-alt-transfer-source), plus options of BIND 9.16 and older that
 * old configurations may still carry (acache-*, cleaning-interval, dnssec-enable, dnssec-lookaside, ...; from memory of
 * the older ARMs, not re-checked against them), minus what KariDNS implements (those are matched before this list is
 * consulted, so a few names, e.g. "port", are implemented and documented by BIND alike).
 * k_bind_key_options: the key statement of both ARMs has only `algorithm` and `secret`, both implemented, so nothing
 * is "BIND but unimplemented" there. */
static const char *const k_bind_options_options[] = {
  "acache-cleaning-interval", "acache-enable", "allow-new-zones", "allow-notify", "allow-proxy", "allow-proxy-on",
  "allow-query", "allow-query-cache", "allow-query-cache-on", "allow-query-on", "allow-recursion", "allow-recursion-on",
  "allow-transfer", "allow-update", "allow-update-forwarding", "allow-v6-synthesis", "alt-transfer-source",
  "alt-transfer-source-v6", "answer-cookie", "attach-cache", "auth-nxdomain", "auto-dnssec", "automatic-interface-scan",
  "avoid-v4-udp-ports", "avoid-v6-udp-ports", "bindkeys-file", "blackhole", "catalog-zones", "check-dup-records",
  "check-integrity", "check-mx", "check-mx-cname", "check-names", "check-sibling", "check-spf", "check-srv-cname",
  "check-svcb", "check-wildcard", "cleaning-interval", "clients-per-query", "coresize", "datasize", "deallocate-on-exit",
  "deny-answer-addresses", "deny-answer-aliases", "dialup", "disable-algorithms", "disable-ds-digests",
  "disable-empty-zone", "dns64", "dns64-contact", "dns64-server", "dnskey-sig-validity", "dnsrps-enable",
  "dnsrps-library", "dnsrps-options", "dnssec-accept-expired", "dnssec-dnskey-kskonly", "dnssec-enable",
  "dnssec-loadkeys-interval", "dnssec-lookaside", "dnssec-must-be-secure", "dnssec-policy", "dnssec-secure-to-insecure",
  "dnssec-update-mode", "dnssec-validation", "dnstap-identity", "dnstap-output", "dnstap-version", "dscp",
  "dual-stack-servers", "dump-file", "edns-udp-size", "empty-contact", "empty-server", "empty-zones-enable",
  "fake-iquery", "fetch-quota-params", "fetches-per-server", "fetches-per-zone", "files", "flush-zones-on-shutdown",
  "forward", "forwarders", "fstrm-set-buffer-hint", "fstrm-set-flush-timeout", "fstrm-set-input-queue-size",
  "fstrm-set-output-notify-threshold", "fstrm-set-output-queue-model", "fstrm-set-output-queue-size", "fstrm-set-reopen-interval",
  "geoip-directory", "glue-cache", "has-old-clients", "heartbeat-interval", "hostname", "http-listener-clients",
  "http-port", "http-streams-per-connection", "https-port", "interface-interval", "ipv4only-contact", "ipv4only-enable",
  "ipv4only-server", "ixfr-from-differences", "keep-response-order", "key-directory", "lame-ttl", "listen-on",
  "listen-on-v6", "lmdb-mapsize", "lock-file", "maintain-ixfr-base", "managed-keys-directory", "masterfile-format",
  "masterfile-style", "match-mapped-addresses", "max-acache-size", "max-cache-size", "max-cache-ttl", "max-clients-per-query",
  "max-ixfr-log-size", "max-ixfr-ratio", "max-journal-size", "max-ncache-ttl", "max-records", "max-records-per-type",
  "max-recursion-depth", "max-recursion-queries", "max-refresh-time", "max-retry-time", "max-rsa-exponent-size",
  "max-stale-ttl", "max-transfer-idle-in", "max-transfer-idle-out", "max-transfer-time-in", "max-transfer-time-out",
  "max-types-per-name", "max-udp-size", "max-validation-failures-per-fetch", "max-validations-per-fetch",
  "max-zone-ttl", "memstatistics", "memstatistics-file", "message-compression", "min-cache-ttl", "min-ncache-ttl",
  "min-refresh-time", "min-retry-time", "min-transfer-rate-in", "multi-master", "named-xfer", "new-zones-directory", "no-case-compress",
  "nocookie-udp-size", "nosit-udp-size", "notify-delay", "notify-rate", "notify-source", "notify-source-v6",
  "notify-to-soa", "nsec3-test-zone", "nta-lifetime", "nta-recheck", "nxdomain-redirect", "parental-source",
  "parental-source-v6", "preferred-glue", "prefetch", "provide-ixfr", "qname-minimization", "query-source",
  "query-source-v6", "queryport-pool-ports", "queryport-pool-updateinterval", "random-device",
  "recursing-file", "recursion", "recursive-clients", "request-expire", "request-ixfr", "request-nsid",
  "require-server-cookie", "reserved-sockets", "resolver-nonbackoff-tries", "resolver-query-timeout", "resolver-retry-interval",
  "resolver-use-dns64", "response-padding", "response-policy", "reuseport", "rfc2308-type1", "root-delegation-only",
  "root-key-sentinel", "rrset-order", "secroots-file", "send-cookie", "serial-query-rate", "serial-update-method",
  "server-id", "servfail-ttl", "session-keyalg", "session-keyfile", "session-keyname", "sig-signing-nodes",
  "sig-signing-signatures", "sig-signing-type", "sig-validity-interval", "sig0checks-quota", "sig0checks-quota-exempt",
  "sit-secret", "sortlist", "stacksize", "stale-answer-client-timeout", "stale-answer-enable", "stale-answer-ttl",
  "stale-cache-enable", "stale-refresh-time", "startup-notify-rate", "statistics-file", "suppress-initial-notify",
  "synth-from-dnssec", "tcp-advertised-timeout", "tcp-clients", "tcp-keepalive-timeout", "tcp-listen-queue",
  "tcp-receive-buffer", "tcp-send-buffer", "tkey-dhkey", "tkey-domain", "tkey-gssapi-credential", "tkey-gssapi-keytab",
  "tls-port", "topology", "transfer-format", "transfer-message-size", "transfer-source", "transfer-source-v6",
  "transfers-in", "transfers-out", "transfers-per-ns", "treat-cr-as-space", "trust-anchor-telemetry", "try-tcp-refresh",
  "udp-receive-buffer", "udp-send-buffer", "update-check-ksk", "update-quota", "use-alt-transfer-source",
  "use-id-pool", "use-ixfr", "use-queryport-pool", "use-v4-udp-ports", "use-v6-udp-ports", "v6-bias", "validate-except",
  "version", "zero-no-soa-ttl", "zero-no-soa-ttl-cache", "zone-statistics",
  NULL
};

static const char *const k_bind_key_options[] = { NULL };

/* The statement `key` (already read) inside the block `what` (options, key 'name') is not one KariDNS implements.
 * Skips the statement and returns 0 when BIND documents it (warning), else reports a configuration error with the place
 * in the file and returns -1 (the caller frees its partial result and returns -1). */
static int unknown_block_statement(token_ctx_t *ctx, const char *what, const char *const *bind_list, const char *key) {
  if (name_in_list(bind_list, key)) {
    char loc[300];
    ctx_location(ctx, loc, sizeof(loc));
    syslog(LOG_WARNING, "[Config] %s: %s: '%.64s' is a BIND option that KariDNS does not implement; it is ignored", loc, what, key);
    fprintf(stderr, "[WARNING] %s: %s: '%.64s' is a BIND option that KariDNS does not implement; it is ignored\n", loc, what, key);
    skip_unknown_block(ctx);
    return 0;
  }
  conf_error(ctx, what, "unknown option '%.64s' (neither a KariDNS option nor a BIND option for this statement; check the spelling)", key);
  return -1;
}

/* key <name> { algorithm <string>; secret <string>; };  after the word `key` has been read (BIND 9.20 ARM "key Block Definition and Usage"):
 * top level and inside view { }.  Returns the key (heap, next == NULL), or NULL after an error has been reported. */
static tsig_key_t *parse_key_block(token_ctx_t *ctx) {
  char db[96];
  tsig_key_t *tsig = NULL;
  char *key_prop = NULL, *val = NULL;
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_STRING || !tok.value) {
    free_token(&tok);
    if (ctx) ctx->error_occurred = true;
    return NULL;
  }
  tsig = safe_calloc_or_die(1, sizeof(tsig_key_t));
  if (!tsig) { free_token(&tok); if (ctx) ctx->error_occurred = true; return NULL; }
  tsig->name = tok.value;
  tok.value = NULL;
  free_token(&tok);
  char what[160];
  snprintf(what, sizeof(what), "key '%.64s'", tsig->name);
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_LBRACE) {
    free_token(&tok);
    goto fail;
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
      goto fail;
    }
    key_prop = tok.value;
    tok.value = NULL;
    free_token(&tok);
    if (strcmp(key_prop, "algorithm") == 0 || strcmp(key_prop, "secret") == 0) {
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_STRING || !tok.value) {
        free_token(&tok);
        goto fail;
      }
      val = tok.value;
      tok.value = NULL;
      free_token(&tok);
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_SEMICOLON) {
        free_token(&tok);
        goto fail;
      }
      free_token(&tok);
      if (strcmp(key_prop, "algorithm") == 0 ? tsig->algorithm != NULL : tsig->secret != NULL) {
        conf_error(ctx, what, "'%s' is given twice", key_prop);
        goto fail;
      }
      if (strcmp(key_prop, "algorithm") == 0) {
        if (!tsig_algorithm_is_supported(val)) {
          syslog(LOG_ERR, "[Config] Unsupported TSIG algorithm: %s", val);
          fprintf(stderr, "[ERROR] Unsupported TSIG algorithm: %s\n", val);
          goto fail;
        }
        if (strstr(val, "md5") || strstr(val, "sha1")) {
          syslog(LOG_WARNING, "[Config] Warning: TSIG algorithm '%s' is deprecated and insecure (RFC 8945)", val);
        }
        tsig->algorithm = val;
        val = NULL;
      } else {
        size_t slen = strlen(val);
        size_t decoded_upper_bound = ((slen + 3) / 4) * 3;
        if (slen == 0 || decoded_upper_bound > sizeof(tsig->secret_decoded)) {
          syslog(LOG_ERR, "[Config] secret too long for algorithm (decodes to %zu bytes, max %zu)", decoded_upper_bound, sizeof(tsig->secret_decoded));
          fprintf(stderr, "[ERROR] secret too long for algorithm\n");
          goto fail;
        }
        int len = EVP_DecodeBlock(tsig->secret_decoded, (const unsigned char *)val, slen);
        if (len < 0) {
          syslog(LOG_ERR, "[Config] key '%s': secret is not valid base64", tsig->name);
          fprintf(stderr, "[ERROR] key '%s': secret is not valid base64\n", tsig->name);
          goto fail;
        }
        int padding = 0;
        if (slen > 0 && val[slen - 1] == '=')
          padding++;
        if (slen > 1 && val[slen - 2] == '=')
          padding++;
        tsig->secret_decoded_len = len - padding;
        if (strcmp(val, KARIDNS_SAMPLE_SECRET_PLACEHOLDER) == 0) {
          syslog(LOG_WARNING, "[Config] key '%s': secret is still the sample placeholder; "
                 "replace it with the output of 'openssl rand -base64 32'", tsig->name);
          fprintf(stderr, "[WARNING] key '%s': secret is still the sample placeholder; "
                  "replace it with the output of 'openssl rand -base64 32'\n", tsig->name);
        }
        tsig->secret = val;
        val = NULL;
      }
    } else if (unknown_block_statement(ctx, what, k_bind_key_options, key_prop) != 0) {
      goto fail;
    }
    free(key_prop);
    key_prop = NULL;
  }
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) {
    conf_error(ctx, what, "expected ';' after '}' but found %s", tok_desc(&tok, db, sizeof(db)));
    free_token(&tok);
    goto fail;
  }
  free_token(&tok);
  /* BIND requires both ("key 'x' must have both 'secret' and 'algorithm' defined").  A key without a secret cannot
   * sign or verify, and the callers would silently fall back to hmac-sha256 for a missing algorithm. */
  if (!tsig->secret || !tsig->algorithm) {
    conf_error(ctx, what, "%s is missing (both 'algorithm' and 'secret' are required)", !tsig->algorithm ? "'algorithm'" : "'secret'");
    goto fail;
  }
  return tsig;
fail:
  free(key_prop);
  free(val);
  if (ctx) ctx->error_occurred = true;
  tsig_keys_free(tsig);
  return NULL;
}

/* B7a: what a DB zone's settings text may contain (db_settings_parse).  The statements karidns-dbloader writes (the output
 * of build_settings() in dns_pdns_reader.c) and the profile texts of karidns_profiles are made of these. */
static const char *const k_db_zone_statements[] = {
  "allow-transfer", "allow-update", "also-notify", "tsig-key", "notify-retries", "notify-retry-interval",
  "notify-retry-backoff", "notify-tcp-timeout", "ixfr-history", "additional-from-auth", "disable-auto-tc-flag", "zone-udp-bufsize",
  "zone-tcp-mss", "zone-tcp-window", "zone-tcp-sndbuf", "transfer-acl-match", "update-acl-match", "masters", "primaries",
  "ecs-trusted-resolvers", "alias-resolver", NULL
};

/* The statement `key` is about to be read in restricted mode: refuse it unless it is on the list, and forget what an
 * earlier statement of the same name set (the later statement replaces it: profile text first, zone text after it). */
static bool restricted_statement(token_ctx_t *ctx, zone_ext_t *x, const char *key) {
  if (!name_in_list(k_db_zone_statements, key)) {
    bool plain = key[0] != '\0' && strlen(key) <= 40;
    for (const char *p = key; plain && *p; p++)
      if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_') plain = false;
    snprintf(ctx->restricted_err, sizeof(ctx->restricted_err),
             "statement '%s' is not allowed in the settings of a database zone", plain ? key : "?");
    ctx->error_occurred = true;
    return false;
  }
  if (strcmp(key, "also-notify") == 0) {
    notify_targets_free(x->also_notify, x->also_notify_count);
    x->also_notify = NULL;
    x->also_notify_count = 0;
    x->also_notify_set = false;
  } else if (strcmp(key, "allow-transfer") == 0) {
    for (int i = 0; i < x->allow_transfer_count; i++) free(x->allow_transfer[i]);
    free(x->allow_transfer);
    free(x->allow_transfer_parsed);
    x->allow_transfer = NULL;
    x->allow_transfer_parsed = NULL;
    x->allow_transfer_count = 0;
    for (int i = 0; i < x->tsig_keys_count; i++) free(x->tsig_keys[i]);
    free(x->tsig_keys);
    x->tsig_keys = NULL;
    x->tsig_keys_count = 0;
  } else if (strcmp(key, "allow-update") == 0) {
    for (int i = 0; i < x->allow_update_count; i++) free(x->allow_update[i]);
    free(x->allow_update);
    free(x->allow_update_parsed);
    x->allow_update = NULL;
    x->allow_update_parsed = NULL;
    x->allow_update_count = 0;
  } else if (strcmp(key, "tsig-key") == 0) {
    free(x->tsig_key);
    x->tsig_key = NULL;
  } else if (strcmp(key, "ecs-trusted-resolvers") == 0) {         /* B8: the later statement replaces the earlier one */
    for (int i = 0; i < x->ecs_trusted_resolvers_count; i++) free(x->ecs_trusted_resolvers[i]);
    free(x->ecs_trusted_resolvers);
    free(x->ecs_trusted_resolvers_parsed);
    x->ecs_trusted_resolvers = NULL;
    x->ecs_trusted_resolvers_parsed = NULL;
    x->ecs_trusted_resolvers_count = 0;
  } else if (strcmp(key, "alias-resolver") == 0) {                 /* B9a: the later statement replaces the earlier one (parse_alias_resolvers() clears it too) */
    for (int i = 0; i < x->alias_resolvers_count; i++) free(x->alias_resolvers[i].ip);
    free(x->alias_resolvers);
    x->alias_resolvers = NULL;
    x->alias_resolvers_count = 0;
  } else if (strcmp(key, "masters") == 0 || strcmp(key, "primaries") == 0) {
    notify_targets_free(x->masters, x->masters_count);
    x->masters = NULL;
    x->masters_count = 0;
    free(x->masters_parsed);
    x->masters_parsed = NULL;
  }
  return true;
}

/* Reads what follows the name of a zone or view up to and including the '{': an optional class, then the brace (BIND 9.20 ARM:
 * `zone <string> [ <class> ] { ... };`, `view <string> [ <class> ] { ... };`).  Only IN is served (case-insensitive); another class is a
 * configuration error with file:line.  0 = the '{' has been read. */
static int read_block_open(token_ctx_t *ctx, const char *what) {
  char db[96];
  conf_token_t tok = get_next_token(ctx);
  if (tok.type == TOKEN_STRING && tok.value && !tok.is_quoted && !ctx->restricted) {
    if (strcasecmp(tok.value, "IN") == 0) {
      free_token(&tok);
      tok = get_next_token(ctx);
    } else if (strcasecmp(tok.value, "CH") == 0 || strcasecmp(tok.value, "CHAOS") == 0 || strcasecmp(tok.value, "HS") == 0 ||
               strcasecmp(tok.value, "HESIOD") == 0 || strncasecmp(tok.value, "CLASS", 5) == 0) {
      conf_error(ctx, what, "class '%.16s' is not supported (only IN)", tok.value);
      free_token(&tok);
      return -1;
    }
  }
  if (tok.type != TOKEN_LBRACE) {
    if (!ctx->restricted)
      conf_error(ctx, what, "expected '{' (or a class, IN) but found %s", tok_desc(&tok, db, sizeof(db)));
    free_token(&tok);
    return -1;
  }
  free_token(&tok);
  return 0;
}

/* BIND 9.20 ARM "Zone Types": hint, stub, static-stub, mirror and redirect belong to a server that resolves or caches.  delegation-only
 * was a type of older BIND versions (the 9.20 ARM has it only as the root-delegation-only / delegation-only options). */
static bool zone_type_is_skipped(const char *t) {
  static const char *const names[] = {"hint", "stub", "static-stub", "mirror", "redirect", "delegation-only", NULL};
  for (size_t i = 0; names[i]; i++)
    if (strcasecmp(t, names[i]) == 0) return true;
  return false;
}

/* The statements of a zone block after the one just read, up to and including the closing "};" */
static int skip_rest_of_zone_block(token_ctx_t *ctx) {
  int depth = 0;
  for (;;) {
    conf_token_t tok = get_next_token(ctx);
    if (tok.type == TOKEN_EOF) {
      free_token(&tok);
      if (ctx) ctx->error_occurred = true;
      return -1;
    }
    bool close = tok.type == TOKEN_RBRACE && depth == 0;
    if (tok.type == TOKEN_LBRACE) depth++;
    else if (tok.type == TOKEN_RBRACE && depth > 0) depth--;
    free_token(&tok);
    if (close) break;
  }
  conf_token_t tok = get_next_token(ctx);
  bool ok = tok.type == TOKEN_SEMICOLON;
  free_token(&tok);
  return ok ? 0 : -1;
}

static int parse_zone_body(token_ctx_t *ctx, zone_config_t *zone, zone_config_t **zone_out);
static int parse_notify_mode(token_ctx_t *ctx, const char *what, uint8_t *out);
static int masters_build_parsed(zone_ext_t *x);

static int parse_zone_block(token_ctx_t *ctx, zone_config_t **zone_out) {
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_STRING) {
    free_token(&tok);
    return -1;
  }
  zone_config_t *zone = safe_calloc_or_die(1, sizeof(zone_config_t));
  if (!zone) {
    free_token(&tok);
    if (ctx) ctx->error_occurred = true;
    return -1;
  }
  /* 指定されたオプションはまず x に溜め、1 つも指定が無ければ最後に捨てる (zone->ext == NULL = 全既定) */
  zone_ext_t *x = safe_calloc_or_die(1, sizeof(zone_ext_t));
  if (!x) {
    free(zone);
    free_token(&tok);
    if (ctx) ctx->error_occurred = true;
    return -1;
  }
  zone->ext = x;
  zone->domain = tok.value;
  tok.value = NULL;
  free_token(&tok);
  if (!zone->domain) {
    free_zone_config(zone);
    if (ctx) ctx->error_occurred = true;
    return -1;
  }
  /* ゾーン名はゾーンデータ・クエリ名と同じ正規形 (dns_wire.h) の絶対名にする (R-29)。
   * 正規形が 255 文字を超える名前はゾーン名として扱わない (ゾーンのエントリは 256 バイト)。 */
  char norm[DNS_NAME_TEXT_SIZE];
  size_t nl = dns_name_normalize(zone->domain, norm, sizeof(norm) - 1);
  if (nl != (size_t)-1 && (nl == 0 || dns_name_len_no_root(norm, nl) == nl)) {
    norm[nl++] = '.'; // 相対名 (末尾ドットなし) を絶対名に。"" はルート
    norm[nl] = '\0';
  }
  if (nl == (size_t)-1 || nl > 255) {
    syslog(LOG_ERR, "[Config] invalid zone name '%s' (bad escape, empty label, or name too long)", zone->domain);
    fprintf(stderr, "[ERROR] invalid zone name '%s' (bad escape, empty label, or name too long)\n", zone->domain);
    free_zone_config(zone);
    if (ctx) ctx->error_occurred = true;
    return -1;
  }
  if (strcmp(norm, zone->domain) != 0) {
    char *copy = strdup(norm);
    if (copy) {
      free(zone->domain);
      zone->domain = copy;
    }
  }
  return parse_zone_body(ctx, zone, zone_out);
}

/* "{ statements };" of a zone whose name and (empty) ext are in place.  Owns zone: freed on every failure. */
static int parse_zone_body(token_ctx_t *ctx, zone_config_t *zone, zone_config_t **zone_out) {
  zone_ext_t *x = zone->ext;
  int nr_rc = 0;
  conf_token_t tok;
  {
    char zw[DNS_NAME_TEXT_SIZE + 16];
    snprintf(zw, sizeof(zw), "zone '%.255s'", zone->domain ? zone->domain : "");
    if (read_block_open(ctx, zw) != 0) {
      free_zone_config(zone);
      return -1;
    }
  }
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
    char *key = tok.value;
    tok.value = NULL;
    free_token(&tok);
    if (ctx->restricted && !restricted_statement(ctx, x, key)) {
      free(key);
      free_zone_config(zone);
      return -1;
    }
    if (strcmp(key, "masters") == 0 || strcmp(key, "primaries") == 0) {
      /* BIND 9.20 ARM "primaries": [ port <n> ] { ( <list> | <ip> [ port <n> ] ) [ key <name> ]; ... };  A later statement replaces the
       * earlier one.  List names are expanded when the whole file is read (resolve_all_notify_targets), which also builds masters_parsed;
       * the settings text of a database zone has no lists, so it is built here. */
      char what[DNS_NAME_TEXT_SIZE + 32];
      snprintf(what, sizeof(what), "zone '%.255s' %s", zone->domain ? zone->domain : "", key);
      notify_targets_free(x->masters, x->masters_count);
      x->masters = NULL;
      x->masters_count = 0;
      if (parse_notify_targets(ctx, what, &x->masters, &x->masters_count, true) != 0) {
        free(key);
        free_zone_config(zone);
        return -1;
      }
      if (ctx->restricted && masters_build_parsed(x) != 0) {
        ctx->error_occurred = true;
        free(key);
        free_zone_config(zone);
        return -1;
      }
    } else if (strcmp(key, "notify") == 0) {
      char what[DNS_NAME_TEXT_SIZE + 32];
      snprintf(what, sizeof(what), "zone '%.255s' notify", zone->domain ? zone->domain : "");
      if (parse_notify_mode(ctx, what, &x->notify_mode) != 0) {
        free(key);
        free_zone_config(zone);
        return -1;
      }
    } else if (strcmp(key, "also-notify") == 0) {
      /* a later also-notify statement replaces the earlier one; an empty one overrides the view's and options' list (BIND 9.20 ARM) */
      char what[DNS_NAME_TEXT_SIZE + 32];
      snprintf(what, sizeof(what), "zone '%.255s' also-notify", zone->domain ? zone->domain : "");
      notify_targets_free(x->also_notify, x->also_notify_count);
      x->also_notify = NULL;
      x->also_notify_count = 0;
      x->also_notify_set = true;
      if (parse_notify_targets(ctx, what, &x->also_notify,
                               &x->also_notify_count, false) != 0) {
        free(key);
        free_zone_config(zone);
        return -1;
      }
    } else if (strcmp(key, "allow-transfer") == 0 || strcmp(key, "allow-update") == 0) {
      if (parse_zone_acl_stmt(ctx, zone, x, key[6] == 't') != 0) {
        free(key); free_zone_config(zone); return -1;
      }
    } else if (strcmp(key, "allow-query") == 0 || strcmp(key, "allow-query-on") == 0 || strcmp(key, "allow-notify") == 0) {
      /* BIND 9.20 ARM: a zone's statement overrides the view's and options' */
      char awhat[DNS_NAME_TEXT_SIZE + 32];
      snprintf(awhat, sizeof(awhat), "zone '%.255s' %s", zone->domain ? zone->domain : "", key);
      aml_t **slot = strcmp(key, "allow-query") == 0 ? &x->acl.query
                     : strcmp(key, "allow-query-on") == 0 ? &x->acl.query_on : &x->acl.notify;
      if (parse_aml_slot(ctx, awhat, slot) != 0) {
        free(key); free_zone_config(zone); return -1;
      }
    } else if (strcmp(key, "update-policy") == 0) {
      char uwhat[DNS_NAME_TEXT_SIZE + 48];
      snprintf(uwhat, sizeof(uwhat), "zone '%.255s'", zone->domain ? zone->domain : "");
      if (parse_update_policy(ctx, uwhat, zone->domain ? zone->domain : "", x) != 0) {
        free(key);
        free_zone_config(zone);
        return -1;
      }
    } else if (zv_option_name(key)) {
      /* batch 7: max-records, max-records-per-type, max-types-per-name, max-zone-ttl, serial-update-method, masterfile-format, check-* */
      char zwhat[DNS_NAME_TEXT_SIZE + 48];
      snprintf(zwhat, sizeof(zwhat), "zone '%.255s'", zone->domain ? zone->domain : "");
      if (parse_zv_option(ctx, zwhat, key, &x->zv, true) != 0) {
        free(key);
        free_zone_config(zone);
        return -1;
      }
    } else if (xo_option_name(key)) {
      /* batch 4: notify-source(-v6), transfer-source(-v6), min/max-refresh/retry-time, max-transfer-*, notify-delay, notify-to-soa,
       * try-tcp-refresh, request-ixfr, provide-ixfr, request-expire, multi-master (BIND 9.20) */
      char xwhat[DNS_NAME_TEXT_SIZE + 48];
      snprintf(xwhat, sizeof(xwhat), "zone '%.255s' %s", zone->domain ? zone->domain : "", key);
      xfr_opts_t *xo = zone_xo_mut(x);
      bool is_ns = strcmp(key, "notify-source") == 0;
      char *legacy = NULL;
      if (!xo || parse_xfr_option(ctx, xwhat, key, xo, true, is_ns ? &legacy : NULL) != 0) {
        if (!xo && ctx) ctx->error_occurred = true;
        free(legacy);
        free(key);
        free_zone_config(zone);
        return -1;
      }
      if (is_ns) {
        free(x->notify_source);
        x->notify_source = legacy;
      }
    } else if (strcmp(key, "type") == 0 || strcmp(key, "file") == 0 ||
               strcmp(key, "file-format") == 0 ||
               strcmp(key, "tsig-key") == 0 ||
               strcmp(key, "catalog-zone") == 0) {
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_STRING) {
        free(key);
        free_zone_config(zone);
        free_token(&tok);
        return -1;
      }
      char *val = tok.value;
      tok.value = NULL;
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
        /* D-23: 型名は小文字の正規名で持つ (使う側は strcmp("master") などで比べる) */
        const char *canon = NULL;
        if (strcasecmp(val, "primary") == 0 || strcasecmp(val, "master") == 0)
          canon = "master";
        else if (strcasecmp(val, "secondary") == 0 || strcasecmp(val, "slave") == 0)
          canon = "slave";
        else if (strcasecmp(val, "program") == 0)
          canon = "program";
        else if (strcasecmp(val, "forward") == 0)
          canon = "forward";
        if (!canon && zone_type_is_skipped(val)) {
          /* a BIND zone type that only a caching / resolving server uses (hint, stub, static-stub, mirror, redirect): the zone is not
           * loaded, the rest of its block is skipped, and the configuration is accepted so that a stock BIND named.conf can be checked
           * and used (BIND 9.20 ARM "Zone Types") */
          char loc[300];
          ctx_location(ctx, loc, sizeof(loc));
          syslog(LOG_WARNING, "[Config] %s: zone '%s': type '%s' is a BIND zone type for resolvers that KariDNS (authoritative only) does not "
                 "implement; the zone is not loaded", loc, zone->domain, val);
          fprintf(stderr, "[WARNING] %s: zone '%s': type '%s' is a BIND zone type for resolvers that KariDNS (authoritative only) does not "
                  "implement; the zone is not loaded\n", loc, zone->domain, val);
          free(key);
          free(val);
          free_zone_config(zone);
          if (skip_rest_of_zone_block(ctx) != 0) return -1;
          *zone_out = NULL;
          return 0;
        }
        if (canon) {
          free(val);
          free(zone->type);
          zone->type = strdup(canon);
        } else {
          syslog(LOG_ERR, "[Config] Unknown zone type '%s' for zone '%s' (expected master/primary, slave/secondary, forward, or program)", val, zone->domain);
          fprintf(stderr, "[ERROR] Unknown zone type '%s' for zone '%s'\n", val, zone->domain);
          free(key);
          free(val);
          free_zone_config(zone);
          return -1;
        }
        if (!zone->type) {
          free(key);
          free_zone_config(zone);
          if (ctx) ctx->error_occurred = true;
          return -1;
        }
      }
      else if (strcmp(key, "file") == 0) {
        free(zone->file); /* 同じ文が 2 回あれば後の値 (前の値を解放する) */
        zone->file = val;
      }
      else if (strcmp(key, "file-format") == 0) {
        if (strcasecmp(val, "bind") != 0 && strcasecmp(val, "tinydns") != 0) {
          syslog(LOG_ERR, "[Config] zone '%s': file-format must be 'bind' or 'tinydns' (got '%s')", zone->domain, val);
          fprintf(stderr, "[ERROR] zone '%s': file-format must be 'bind' or 'tinydns' (got '%s')\n", zone->domain, val);
          free(key);
          free(val);
          free_zone_config(zone);
          return -1;
        }
        free(x->file_format);
        x->file_format = val;
      }
      else if (strcmp(key, "tsig-key") == 0) {
        free(x->tsig_key);
        x->tsig_key = val;
      }
      else if (strcmp(key, "catalog-zone") == 0) {
        if (!parse_config_bool(val, &zone->is_catalog)) {
          report_bad_bool(ctx, zone->domain, key, val);
          free(key);
          free(val);
          free_zone_config(zone);
          return -1;
        }
        free(val);
      }
    } else if (strcmp(key, "program") == 0) {
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_STRING) { free(key); free_zone_config(zone); free_token(&tok); return -1; }
      if (x->program_path) free(x->program_path);
      x->program_path = tok.value;
      tok.value = NULL;
      free_token(&tok);
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_SEMICOLON) { free(key); free_zone_config(zone); free_token(&tok); return -1; }
      free_token(&tok);
    } else if (strcmp(key, "program-args") == 0) {
      if (parse_string_list(ctx, &x->program_args, &x->program_args_count) != 0) {
        free(key); free_zone_config(zone); return -1;
      }
    } else if (strcmp(key, "program-user") == 0) {
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_STRING) { free(key); free_zone_config(zone); free_token(&tok); return -1; }
      if (x->program_user) free(x->program_user);
      x->program_user = tok.value;
      tok.value = NULL;
      free_token(&tok);
      if (!x->program_user) { free(key); free_zone_config(zone); if (ctx) ctx->error_occurred = true; return -1; }
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_SEMICOLON) { free(key); free_zone_config(zone); free_token(&tok); return -1; }
      free_token(&tok);
    } else if (strcmp(key, "program-timeout") == 0) {
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_STRING) { free(key); free_zone_config(zone); free_token(&tok); return -1; }
      char *endptr = NULL;
      unsigned long val_num = strtoul(tok.value, &endptr, 10);
      if (*endptr == '\0') {
        x->program_timeout_ms = (uint32_t)val_num;
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
        x->program_max_failures = (uint32_t)val_num;
      }
      free_token(&tok);
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_SEMICOLON) { free(key); free_zone_config(zone); free_token(&tok); return -1; }
      free_token(&tok);
    } else if (strcmp(key, "alias-resolver") == 0) {
      if (parse_alias_resolvers(ctx, zone->domain ? zone->domain : "zone", &x->alias_resolvers, &x->alias_resolvers_count) != 0) {
        free(key); free_zone_config(zone); return -1;
      }
    } else if (strcmp(key, "forwarders") == 0) {
      if (parse_ip_port_list(ctx, "forwarders", &x->forwarders, &x->forwarders_count) != 0) {
        free(key); free_zone_config(zone); return -1;
      }
    } else if (strcmp(key, "forward-timeout") == 0) {
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_STRING) { free(key); free_zone_config(zone); free_token(&tok); return -1; }
      char *endptr = NULL;
      unsigned long val_num = strtoul(tok.value, &endptr, 10);
      if (*endptr == '\0') {
        x->forward_timeout_ms = (uint32_t)val_num;
      }
      free_token(&tok);
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_SEMICOLON) { free(key); free_zone_config(zone); free_token(&tok); return -1; }
      free_token(&tok);
    } else if (strcmp(key, "rate-limit") == 0) {
      if (parse_rate_limit_config(ctx, &x->rrl) != 0) {
        free(key);
        free_zone_config(zone);
        return -1;
      }
    } else if (strcmp(key, "ecs-tags") == 0) {
      if (parse_ecs_tags_block(ctx, &x->ecs_tags, &x->ecs_tag_count) != 0) {
        free(key);
        free_zone_config(zone);
        return -1;
      }
    } else if (strcmp(key, "location-tags") == 0) {
      if (parse_ecs_tags_block(ctx, &x->location_tags, &x->location_tag_count) != 0) {
        free(key);
        free_zone_config(zone);
        return -1;
      }
    } else if (strcmp(key, "ecs-trusted-resolvers") == 0) {
      if (parse_string_list(ctx, &x->ecs_trusted_resolvers,
                            &x->ecs_trusted_resolvers_count) != 0) {
        free(key);
        free_zone_config(zone);
        return -1;
      }
      free(x->ecs_trusted_resolvers_parsed);
      x->ecs_trusted_resolvers_parsed = acl_list_parse(x->ecs_trusted_resolvers, x->ecs_trusted_resolvers_count);
    } else if (strcmp(key, "additional-from-auth") == 0) {
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_STRING) {
        free(key);
        free_zone_config(zone);
        free_token(&tok);
        return -1;
      }
      x->additional_from_auth_specified = true;
      if (!parse_additional_from_auth(tok.value, &x->additional_from_auth)) {
        report_bad_value(ctx, zone->domain, key, tok.value, "yes, no or in-domain");
        free(key);
        free_zone_config(zone);
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_SEMICOLON) {
        free(key);
        free_zone_config(zone);
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
    } else if (strcmp(key, "disable-auto-tc-flag") == 0) {
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_STRING) {
        free(key);
        free_zone_config(zone);
        free_token(&tok);
        return -1;
      }
      if (!parse_config_bool(tok.value, &x->disable_auto_tc_flag)) {
        report_bad_bool(ctx, zone->domain, key, tok.value);
        free(key);
        free_zone_config(zone);
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_SEMICOLON) {
        free(key);
        free_zone_config(zone);
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
    } else if (strcmp(key, "ixfr-history") == 0) {
      int v = 0;
      if (parse_transport_param(ctx, zone->domain, key, false, 0, IXFR_HISTORY_MAX, &v) != 0) {
        free(key);
        free_zone_config(zone);
        return -1;
      }
      x->ixfr_history = (uint8_t)v;
      x->ixfr_history_set = true;
    } else if (strcmp(key, "max-zone-records") == 0 || strcmp(key, "max-zone-bytes") == 0) {
      /* I2: the limits of one inbound transfer of this zone (the same ranges as the database block) */
      bool recs = strcmp(key, "max-zone-records") == 0;
      int rc = recs ? db_take_uint(ctx, key, false, 2, KARIDNS_DB_MAX_ZONE_RECORDS_MAX, &x->max_zone_records)
                    : db_take_uint(ctx, key, true, KARIDNS_DB_MAX_ZONE_BYTES_MIN, KARIDNS_DB_MAX_ZONE_BYTES_MAX, &x->max_zone_bytes);
      if (rc != 0) {
        free(key);
        free_zone_config(zone);
        return -1;
      }
    } else if ((strncmp(key, "notify-retr", 11) == 0 || strcmp(key, "notify-tcp-timeout") == 0) &&
               (nr_rc = parse_notify_retry_option(ctx, zone->domain, key, &x->notify_retry)) != 0) {
      if (nr_rc < 0) {
        free(key);
        free_zone_config(zone);
        return -1;
      }
    } else if (strcmp(key, "zone-tcp-mss") == 0 || strcmp(key, "zone-tcp-window") == 0 ||
               strcmp(key, "zone-tcp-sndbuf") == 0 || strcmp(key, "zone-udp-bufsize") == 0) {
      int v = 0;
      int rc;
      if (strcmp(key, "zone-tcp-mss") == 0)
        rc = parse_transport_param(ctx, zone->domain, key, false, KARIDNS_TCP_MSS_MIN, KARIDNS_TCP_MSS_MAX, &v);
      else if (strcmp(key, "zone-udp-bufsize") == 0)
        rc = parse_transport_param(ctx, zone->domain, key, false, KARIDNS_UDP_BUFSIZE_MIN, KARIDNS_UDP_BUFSIZE_MAX, &v);
      else
        rc = parse_transport_param(ctx, zone->domain, key, true, KARIDNS_TCP_BUF_MIN, KARIDNS_TCP_BUF_MAX, &v);
      if (rc != 0) {
        free(key);
        free_zone_config(zone);
        return -1;
      }
      if (strcmp(key, "zone-tcp-mss") == 0) x->zone_tcp_mss = v;
      else if (strcmp(key, "zone-tcp-window") == 0) x->zone_tcp_window = v;
      else if (strcmp(key, "zone-tcp-sndbuf") == 0) x->zone_tcp_sndbuf = v;
      else x->zone_udp_bufsize = (uint16_t)v;
    } else if (strcmp(key, "primary-settings") == 0) {
      /* B8t-2: use (default) or ignore the settings the primary sends with the zone */
      tok = get_next_token(ctx);
      bool v = true;
      if (tok.type != TOKEN_STRING || !parse_config_bool(tok.value, &v)) {
        report_bad_bool(ctx, zone->domain, key, tok.type == TOKEN_STRING ? tok.value : "");
        free(key);
        free_zone_config(zone);
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_SEMICOLON) {
        free(key);
        free_zone_config(zone);
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      x->primary_settings_off = !v;
    } else if (strcmp(key, "transfer-acl-match") == 0 || strcmp(key, "update-acl-match") == 0) {
      /* D14: which kinds of entry of allow-transfer / allow-update have to match (docs/karidns.md) */
      tok = get_next_token(ctx);
      uint8_t m = ACL_MATCH_DEFAULT;
      if (tok.type == TOKEN_STRING && tok.value) {
        if (strcasecmp(tok.value, "any") == 0) m = ACL_MATCH_ANY;
        else if (strcasecmp(tok.value, "all") == 0) m = ACL_MATCH_ALL;
      }
      if (m == ACL_MATCH_DEFAULT) {
        report_bad_value(ctx, zone->domain, key, tok.type == TOKEN_STRING ? tok.value : "", "any or all");
        free(key);
        free_zone_config(zone);
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_SEMICOLON) {
        free(key);
        free_zone_config(zone);
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      if (key[0] == 't') x->transfer_acl_match = m;
      else x->update_acl_match = m;
    } else if (strcmp(key, "in-view") == 0) {
      /* BIND: the zone is the one of another view.  Skipping the statement would leave an empty primary zone, so it is an error until
       * zones can be shared between views */
      char iw[DNS_NAME_TEXT_SIZE + 16];
      snprintf(iw, sizeof(iw), "zone '%.255s'", zone->domain);
      conf_error(ctx, iw, "'in-view' (a zone shared with another view) is not supported");
      free(key);
      free_zone_config(zone);
      return -1;
    } else if (unknown_statement(ctx, "zone", zone->domain, key, false) != 0) {
      free(key);
      free_zone_config(zone);
      return -1;
    }
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
    if (!zone->type) { free_zone_config(zone); if (ctx) ctx->error_occurred = true; return -1; }
  }
  if (zone->type && strcasecmp(zone->type, "program") == 0) {
    if (zone->file) {
      syslog(LOG_WARNING, "[Config] Zone '%s' is type 'program' but has 'file' configured; ignoring file", zone->domain);
    }
    if (x->masters_count > 0) {
      syslog(LOG_WARNING, "[Config] Zone '%s' is type 'program' but has 'masters' configured; ignoring masters", zone->domain);
    }
  }
  if (zone->type && strcasecmp(zone->type, "forward") == 0) {
    if (zone->file) {
      syslog(LOG_WARNING, "[Config] Zone '%s' is type 'forward' but has 'file' configured; ignoring file", zone->domain);
    }
    if (x->masters_count > 0) {
      syslog(LOG_WARNING, "[Config] Zone '%s' is type 'forward' but has 'masters' configured; ignoring masters", zone->domain);
    }
  }
  if (x->allow_update_count > 0 && zone->type &&
      (strcasecmp(zone->type, "slave") == 0 || strcasecmp(zone->type, "secondary") == 0)) {
    syslog(LOG_WARNING,
           "[Config] Zone '%s' is type 'slave'/'secondary' but has 'allow-update' configured; "
           "Dynamic Update requests to secondary zones are refused at runtime (REFUSED; updates are not forwarded to the primary)",
           zone->domain);
    fprintf(stderr,
           "[WARNING] Zone '%s' is type 'slave'/'secondary' but has 'allow-update' configured; "
           "Dynamic Update requests to secondary zones are refused at runtime (REFUSED; updates are not forwarded to the primary)\n",
           zone->domain);
  }
  /* 何も指定されなかった (全ゼロ) なら ext を持たない。x は calloc なのでパディングもゼロ */
  if (memcmp(x, &zone_ext_default, sizeof(*x)) == 0) {
    free(x);
    zone->ext = NULL;
  }
  *zone_out = zone;
  return 0;
}

/* ---- settings text of DB zones (B7a, beta design 1.3, 3.5) ---- */

static void db_set_err(char *err, size_t errlen, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void db_set_err(char *err, size_t errlen, const char *fmt, ...) {
  if (!err || errlen == 0) return;
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(err, errlen, fmt, ap);
  va_end(ap);
}

/* The entries of an ACL must be something this module can evaluate without karidns.conf: an address, a prefix, any, none
 * (each with an optional leading "!").  Names of ACLs of karidns.conf, localhost and localnets are refused: they would be
 * read as something else (a key name in allow-update) or never match. */
static bool db_acl_entries_ok(char *const *list, int count, bool keys_allowed, char *err, size_t errlen, const char *what) {
  for (int i = 0; i < count; i++) {
    const char *e = list[i] ? list[i] : "";
    const char *t = e[0] == '!' ? e + 1 : e;
    if (acl_entry_is_address(t)) continue;
    /* allow-update keeps a key as a bare name; a negated or odd name is not a key */
    bool name_ok = keys_allowed && e[0] != '!' && e[0] != '\0' && strlen(e) <= 255 && !acl_name_is_builtin(e);
    for (const char *p = e; name_ok && *p; p++)
      if ((unsigned char)*p < 0x21 || (unsigned char)*p > 0x7E) name_ok = false;
    if (!name_ok) {
      db_set_err(err, errlen, "%s has an entry that is not an address, prefix, any, none%s", what,
                 keys_allowed ? " or key name" : "");
      return false;
    }
  }
  return true;
}

static bool db_ip_literal_ok(const char *s) {
  struct in_addr a4;
  struct in6_addr a6;
  return s && (inet_pton(AF_INET, s, &a4) == 1 || inet_pton(AF_INET6, s, &a6) == 1);
}

zone_ext_shared_t *db_settings_parse(const char *text, size_t len, char *err, size_t errlen) {
  if (err && errlen) err[0] = '\0';
  if (!text) return NULL;
  if (len > (size_t)262144) {
    db_set_err(err, errlen, "settings text is too long");
    return NULL;
  }
  char *buf = malloc(len + 16);
  zone_config_t *zone = calloc(1, sizeof(*zone));
  zone_ext_t *x = calloc(1, sizeof(*x));
  if (!buf || !zone || !x) {
    free(buf);
    free(zone);
    free(x);
    db_set_err(err, errlen, "out of memory");
    return NULL;
  }
  buf[0] = '{';
  memcpy(buf + 1, text, len);
  memcpy(buf + 1 + len, "\n};", 4);        /* a text that ends inside a comment still gets its closing brace */
  zone->domain = strdup("settings.");
  zone->type = strdup("master");
  zone->ext = x;
  if (!zone->domain || !zone->type) {
    free_zone_config(zone);
    free(buf);
    db_set_err(err, errlen, "out of memory");
    return NULL;
  }
  token_ctx_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.stack[0].src = buf;
  ctx.stack[0].len = len + 4;
  ctx.restricted = true;
  ctx.no_include = true;
  zone_config_t *out = NULL;
  int rc = parse_zone_body(&ctx, zone, &out);      /* frees zone on failure */
  zone_ext_shared_t *sh = NULL;
  if (rc == 0 && !ctx.error_occurred) {
    conf_token_t tail = get_next_token(&ctx);       /* a stray '}' in the text would end the block early */
    bool trailing = tail.type != TOKEN_EOF;
    free_token(&tail);
    if (trailing) db_set_err(err, errlen, "unbalanced braces in the settings text");
    else if (!out->ext) out->ext = calloc(1, sizeof(zone_ext_t));
    zone_ext_t *ox = out->ext;
    if (!trailing && !ox) {
      db_set_err(err, errlen, "out of memory");
    } else if (!trailing) {
      const char *bad = NULL;
      if (!db_acl_entries_ok(ox->allow_transfer, ox->allow_transfer_count, false, err, errlen, "allow-transfer") ||
          !db_acl_entries_ok(ox->allow_update, ox->allow_update_count, true, err, errlen, "allow-update") ||
          !db_acl_entries_ok(ox->ecs_trusted_resolvers, ox->ecs_trusted_resolvers_count, false, err, errlen, "ecs-trusted-resolvers"))
        bad = err;
      /* the database text names addresses only: no list name (karidns.conf is not available to it), no TSIG key (the secret would
       * have to be found by a name the database chose) */
      for (int i = 0; !bad && i < ox->also_notify_count; i++) {
        if (!db_ip_literal_ok(ox->also_notify[i].ip)) {
          db_set_err(err, errlen, "also-notify has an entry that is not an IP address");
          bad = err;
        } else if (ox->also_notify[i].key) {
          db_set_err(err, errlen, "also-notify has an entry with a key, which a database zone cannot use");
          bad = err;
        }
      }
      for (int i = 0; !bad && i < ox->masters_count; i++)
        if (!db_ip_literal_ok(ox->masters[i].ip)) {
          db_set_err(err, errlen, "masters has an entry that is not an IP address");
          bad = err;
        } else if (ox->masters[i].key) {
          db_set_err(err, errlen, "masters has an entry with a key, which a database zone cannot use");
          bad = err;
        }
      if (!bad && ox->masters_count > 32) {
        db_set_err(err, errlen, "masters has more than 32 entries");
        bad = err;
      }
      for (int i = 0; !bad && i < ox->tsig_keys_count; i++)
        if (!ox->tsig_keys[i] || !ox->tsig_keys[i][0]) {
          db_set_err(err, errlen, "allow-transfer has an empty key name");
          bad = err;
        }
      if (!bad && ox->tsig_key && !ox->tsig_key[0]) {
        db_set_err(err, errlen, "tsig-key is empty");
        bad = err;
      }
      if (!bad) {
        sh = calloc(1, sizeof(*sh));
        if (!sh) {
          db_set_err(err, errlen, "out of memory");
        } else {
          sh->ext = *ox;                            /* the pointers move to the shared object */
          free(ox);
          out->ext = NULL;
          sh->ext.db_acl_ceiling = true;
          atomic_init(&sh->refs, 1);
        }
      }
    }
    free_zone_config(out);
  } else {
    if (rc == 0) free_zone_config(out);
    if (err && errlen && !err[0])
      db_set_err(err, errlen, "%s", ctx.restricted_err[0] ? ctx.restricted_err : "syntax error or invalid value in the settings text");
  }
  config_lexer_cleanup(&ctx);
  free(buf);
  return sh;
}

const char *db_settings_missing_key(const zone_ext_t *x, const server_config_t *cfg) {
  if (!x) return NULL;
  for (int i = 0; i < x->tsig_keys_count; i++)
    if (!cfg || !key_name_is_defined(cfg->keys, x->tsig_keys[i])) return x->tsig_keys[i];
  if (x->tsig_key && (!cfg || !key_name_is_defined(cfg->keys, x->tsig_key))) return x->tsig_key;
  for (int i = 0; i < x->allow_update_count; i++) {
    const char *e = x->allow_update[i];
    if (!e || acl_entry_is_address(e[0] == '!' ? e + 1 : e)) continue;
    if (!cfg || !key_name_is_defined(cfg->keys, e)) return e;
  }
  return NULL;
}

bool db_acl_ceiling_configured(const server_config_t *cfg) {
  return cfg && cfg->database.enabled && (cfg->database.acl_ceiling_count > 0 || cfg->database.acl_ceiling_keys_count > 0);
}

static int parse_buffer_size_value(const char *str) {
  if (!str || !*str) return 0;
  char *endptr = NULL;
  long long val = strtoll(str, &endptr, 10);
  if (val <= 0) return 0;
  long long mult = 1;
  if (endptr && *endptr) {
    if (*endptr == 'k' || *endptr == 'K') mult = 1024LL;
    else if (*endptr == 'm' || *endptr == 'M') mult = 1024LL * 1024;
    else if (*endptr == 'g' || *endptr == 'G') mult = 1024LL * 1024 * 1024;
  }
  /* clamp before multiplying: "9999999999G" would overflow long long (UB) */
  if (val > INT_MAX / mult) return INT_MAX;
  val *= mult;
  if (val > INT_MAX) val = INT_MAX;
  return (int)val;
}

/* ---- Batch 7: dnstap in the BIND 9.20 grammar (lib/isccfg/namedconf.c cfg_type_dnstap: a list of `<type> [query | response];` with type all, auth,
 * client, forwarder, resolver or update; dnstap-output, dnstap-identity, dnstap-version, fstrm-set-*; lib/isccfg/check.c: dnstap-output is
 * required with dnstap).  The first word inside dnstap { } tells the two grammars apart; mixing them is an error.  KariDNS sends AUTH_QUERY and
 * AUTH_RESPONSE only (to a UNIX socket), so `auth` and `all` select those and the other types are accepted with a note. ---- */
static bool dnstap_is_bind_type(const char *w) {
  static const char *const types[] = { "all", "auth", "client", "forwarder", "resolver", "update", NULL };
  for (size_t i = 0; types[i]; i++)
    if (strcasecmp(types[i], w) == 0) return true;
  return false;
}

/* set a dnstap string from one of the two grammars; a value that differs from one the other grammar set is an error */
static int dnstap_set_string(token_ctx_t *ctx, char **field, char *origin, char from, const char *what, const char *val) {
  if (*field && *origin && *origin != from && strcmp(*field, val) != 0) {
    conf_error(ctx, what, "'%.64s' differs from '%.64s', which the %s grammar of dnstap set; write one of them, or the same value in both", val, *field,
               from == 'b' ? "dnstap { socket / identity / version }" : "dnstap-output / dnstap-identity / dnstap-version");
    return -1;
  }
  char *copy = strdup(val);
  if (!copy) { if (ctx) ctx->error_occurred = true; return -1; }
  free(*field);
  *field = copy;
  *origin = from;
  return 0;
}

/* the entries of dnstap { auth; auth query; ... }; `first` is the first word, already read.  Reads up to and including the '}' and the ';' */
static int parse_dnstap_bind_entries(token_ctx_t *ctx, server_config_t *config, conf_token_t first) {
  dnstap_config_t *d = &config->dnstap;
  d->bind_form = true;
  d->log_auth_query = d->log_auth_response = false;
  conf_token_t tok = first;
  for (;;) {
    if (tok.type == TOKEN_RBRACE) { free_token(&tok); break; }
    if (tok.type != TOKEN_STRING || !tok.value) { free_token(&tok); return -1; }
    if (!dnstap_is_bind_type(tok.value)) {
      conf_error(ctx, "dnstap", "'%.64s' is not a dnstap message type (all, auth, client, forwarder, resolver, update); the KariDNS statements (socket, identity, ...) "
                 "cannot be mixed with the BIND list", tok.value);
      free_token(&tok);
      return -1;
    }
    char type[16];
    snprintf(type, sizeof(type), "%s", tok.value);
    free_token(&tok);
    tok = get_next_token(ctx);
    bool q = true, r = true;
    if (tok.type == TOKEN_STRING && tok.value && (strcasecmp(tok.value, "query") == 0 || strcasecmp(tok.value, "response") == 0)) {
      q = strcasecmp(tok.value, "query") == 0;
      r = !q;
      free_token(&tok);
      tok = get_next_token(ctx);
    }
    if (tok.type != TOKEN_SEMICOLON) { free_token(&tok); return -1; }
    free_token(&tok);
    if (strcasecmp(type, "auth") == 0 || strcasecmp(type, "all") == 0) {
      if (q) d->log_auth_query = true;
      if (r) d->log_auth_response = true;
      if (strcasecmp(type, "all") == 0)
        conf_warn_here(ctx, "dnstap", "all: only the auth messages (AUTH_QUERY, AUTH_RESPONSE) are sent; KariDNS has no client, resolver, forwarder or update messages");
    } else if (strcasecmp(type, "update") == 0) {
      conf_warn_here(ctx, "dnstap", "update is accepted, no effect in KariDNS: the dnstap UPDATE_QUERY / UPDATE_RESPONSE messages are not sent");
    } else {
      conf_warn_here(ctx, "dnstap", "%s is accepted, no effect in KariDNS: it is an authoritative server and sends no %s messages", type, type);
    }
    tok = get_next_token(ctx);
  }
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) { free_token(&tok); return -1; }
  free_token(&tok);
  return 0;
}

/* options { dnstap-output ( file | unix ) "path" [size ..] [versions ..] [suffix ..]; }: a UNIX socket is what KariDNS writes to.  A file would be a new
 * file opened by the Backend (CLAUDE.md rule 2), so it is refused; size, versions and suffix go with a file only (BIND check.c). */
static int parse_dnstap_output(token_ctx_t *ctx, server_config_t *config) {
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_STRING || !tok.value) { free_token(&tok); return -1; }
  bool is_unix = strcasecmp(tok.value, "unix") == 0;
  if (!is_unix && strcasecmp(tok.value, "file") != 0) {
    conf_error(ctx, "options dnstap-output", "invalid mode '%.64s' (expected file or unix)", tok.value);
    free_token(&tok);
    return -1;
  }
  free_token(&tok);
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_STRING || !tok.value) { free_token(&tok); return -1; }
  char *path = tok.value;
  tok.value = NULL;
  free_token(&tok);
  bool extra = false;
  for (;;) {
    tok = get_next_token(ctx);
    if (tok.type == TOKEN_SEMICOLON) { free_token(&tok); break; }
    if (tok.type != TOKEN_STRING || !tok.value ||
        (strcasecmp(tok.value, "size") != 0 && strcasecmp(tok.value, "versions") != 0 && strcasecmp(tok.value, "suffix") != 0)) {
      free_token(&tok);
      free(path);
      return -1;
    }
    extra = true;
    free_token(&tok);
    tok = get_next_token(ctx);   /* the value of size / versions / suffix */
    if (tok.type != TOKEN_STRING) { free_token(&tok); free(path); return -1; }
    free_token(&tok);
  }
  int rc = 0;
  if (!is_unix) {
    conf_error(ctx, "options dnstap-output", "mode file is not supported: KariDNS sends dnstap messages to a UNIX socket (dnstap-output unix \"%.200s\")", path);
    rc = -1;
  } else if (extra) {
    conf_error(ctx, "options dnstap-output", "size, versions and suffix cannot be set with mode unix");
    rc = -1;
  } else {
    rc = dnstap_set_string(ctx, &config->dnstap.socket_path, &config->dnstap.origin_socket, 'b', "options dnstap-output", path);
  }
  free(path);
  return rc;
}

/* options { dnstap-identity ( "text" | none | hostname ); dnstap-version ( "text" | none ); } */
static int parse_dnstap_text(token_ctx_t *ctx, server_config_t *config, const char *key) {
  bool is_id = strcmp(key, "dnstap-identity") == 0;
  char what[32];
  snprintf(what, sizeof(what), "options %s", key);
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_STRING || !tok.value) { free_token(&tok); return -1; }
  bool none = !tok.is_quoted && strcasecmp(tok.value, "none") == 0;
  bool host = is_id && !tok.is_quoted && strcasecmp(tok.value, "hostname") == 0;
  char hn[256];
  const char *val = tok.value;
  if (host) {
    if (gethostname(hn, sizeof(hn)) != 0) hn[0] = '\0';
    hn[sizeof(hn) - 1] = '\0';
    val = hn;
  }
  int rc = 0;
  if (!none && !(host && !val[0]))
    rc = is_id ? dnstap_set_string(ctx, &config->dnstap.identity, &config->dnstap.origin_identity, 'b', what, val)
               : dnstap_set_string(ctx, &config->dnstap.version, &config->dnstap.origin_version, 'b', what, val);
  free_token(&tok);
  if (rc != 0) return -1;
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) { free_token(&tok); return -1; }
  free_token(&tok);
  return 0;
}

static int parse_dnstap_block(token_ctx_t *ctx, server_config_t *config) {
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_LBRACE) { free_token(&tok); return -1; }
  free_token(&tok);
  config->dnstap.enabled = true;
  config->dnstap.queue_size = 4096;
  bool msg_type_specified = false;
  /* the first word tells the grammars apart: a message type is BIND's list, anything else a KariDNS statement */
  conf_token_t first = get_next_token(ctx);
  if (first.type == TOKEN_STRING && first.value && dnstap_is_bind_type(first.value)) return parse_dnstap_bind_entries(ctx, config, first);
  bool have_first = true;
  while (1) {
    if (have_first) { tok = first; have_first = false; }
    else tok = get_next_token(ctx);
    if (tok.type == TOKEN_RBRACE) { free_token(&tok); break; }
    if (tok.type != TOKEN_STRING) { free_token(&tok); return -1; }
    char *key_prop = tok.value;
    tok.value = NULL;
    free_token(&tok);
    if (dnstap_is_bind_type(key_prop)) {
      conf_error(ctx, "dnstap", "'%.64s' is a message type of the BIND list (dnstap { auth; }); it cannot be mixed with the KariDNS statements (socket, identity, ...)", key_prop);
      free(key_prop);
      return -1;
    }
    tok = get_next_token(ctx);
    if (tok.type != TOKEN_STRING) { free(key_prop); free_token(&tok); return -1; }
    char *val = tok.value;
    tok.value = NULL;
    free_token(&tok);
    tok = get_next_token(ctx);
    if (tok.type != TOKEN_SEMICOLON) { free(key_prop); free(val); free_token(&tok); return -1; }
    free_token(&tok);

    if (strcmp(key_prop, "socket") == 0 || strcmp(key_prop, "socket-path") == 0 || strcmp(key_prop, "identity") == 0 || strcmp(key_prop, "version") == 0) {
      bool is_sock = key_prop[0] == 's', is_id = key_prop[0] == 'i';
      int src = dnstap_set_string(ctx, is_sock ? &config->dnstap.socket_path : is_id ? &config->dnstap.identity : &config->dnstap.version,
                                  is_sock ? &config->dnstap.origin_socket : is_id ? &config->dnstap.origin_identity : &config->dnstap.origin_version, 'k',
                                  "dnstap", val);
      free(val);
      if (src != 0) { free(key_prop); return -1; }
    } else if (strcmp(key_prop, "queue-size") == 0 || strcmp(key_prop, "queue_size") == 0) {
      config->dnstap.queue_size = (uint32_t)strtoul(val, NULL, 10);
      free(val);
    } else if (strcmp(key_prop, "log-queries") == 0 || strcmp(key_prop, "auth-query") == 0 ||
               strcmp(key_prop, "log-responses") == 0 || strcmp(key_prop, "auth-response") == 0 ||
               strcmp(key_prop, "require-connect") == 0) {
      bool *dst = &config->dnstap.require_connect;
      if (strcmp(key_prop, "log-queries") == 0 || strcmp(key_prop, "auth-query") == 0) {
        dst = &config->dnstap.log_auth_query;
        msg_type_specified = true;
      } else if (strcmp(key_prop, "log-responses") == 0 || strcmp(key_prop, "auth-response") == 0) {
        dst = &config->dnstap.log_auth_response;
        msg_type_specified = true;
      }
      if (!parse_config_bool(val, dst)) {
        report_bad_bool(ctx, NULL, key_prop, val);
        free(val);
        free(key_prop);
        return -1;
      }
      free(val);
    } else {
      free(val);
    }
    free(key_prop);
  }
  if (!msg_type_specified) {
    // どちらも指定されていなければ従来どおりクエリと応答の両方を出力する
    config->dnstap.log_auth_query = true;
    config->dnstap.log_auth_response = true;
  }
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) { free_token(&tok); return -1; }
  free_token(&tok);
  return 0;
}

/* ---- options { database { ... }; } and the per-view database options (beta design 7.1) ---------------------------- */

static void db_cfg_error(token_ctx_t *ctx, const char *fmt, ...) {
  char msg[512];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);
  syslog(LOG_ERR, "[Config] %s", msg);
  fprintf(stderr, "[ERROR] %s\n", msg);
  if (ctx) ctx->error_occurred = true;
}

/* The value of "<key> <string>;" is a UTF-8 string without control characters of 1..maxlen bytes (paths and schema
 * names are used byte for byte, so nothing is decoded here).  *dst takes the string (a previous value is freed). */
static int db_take_string(token_ctx_t *ctx, const char *scope, const char *key, size_t maxlen, char **dst) {
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_STRING || !tok.value) { free_token(&tok); return -1; }
  char *val = tok.value;
  tok.value = NULL;
  free_token(&tok);
  size_t n = strlen(val);
  if (n == 0 || n > maxlen || !dns_path_is_valid_utf8((const unsigned char *)val, n)) {
    db_cfg_error(ctx, "%s: invalid %s value (expected 1..%zu bytes of UTF-8 without control characters)", scope,
                 key, maxlen);
    free(val);
    return -1;
  }
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) { free(val); free_token(&tok); return -1; }
  free_token(&tok);
  free(*dst);
  *dst = val;
  return 0;
}

/* "<key> <number>;" with an optional K/M/G suffix (1024 based) when allow_suffix.  Digits only, lo..hi. */
static int db_take_uint(token_ctx_t *ctx, const char *key, bool allow_suffix, uint64_t lo, uint64_t hi,
                        uint64_t *out) {
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_STRING || !tok.value) { free_token(&tok); return -1; }
  const char *s = tok.value;
  bool ok = false;
  uint64_t v = 0;
  if (isdigit((unsigned char)s[0])) {
    char *end = NULL;
    errno = 0;
    unsigned long long x = strtoull(s, &end, 10);
    if (errno == 0) {
      uint64_t mult = 1;
      if (allow_suffix && (*end == 'k' || *end == 'K')) { mult = 1ull << 10; end++; }
      else if (allow_suffix && (*end == 'm' || *end == 'M')) { mult = 1ull << 20; end++; }
      else if (allow_suffix && (*end == 'g' || *end == 'G')) { mult = 1ull << 30; end++; }
      if (*end == '\0' && x <= UINT64_MAX / mult) {
        v = (uint64_t)x * mult;
        ok = v >= lo && v <= hi;
      }
    }
  }
  if (!ok) {
    char expected[96];
    snprintf(expected, sizeof(expected), "%llu..%llu%s", (unsigned long long)lo, (unsigned long long)hi,
             allow_suffix ? ", K/M/G suffix allowed" : "");
    report_bad_value(ctx, NULL, key, s, expected);
    free_token(&tok);
    return -1;
  }
  free_token(&tok);
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) { free_token(&tok); return -1; }
  free_token(&tok);
  *out = v;
  return 0;
}

static int parse_database_option(token_ctx_t *ctx, database_config_t *db, const char *key) {
  uint64_t u = 0;
  if (strcmp(key, "driver") == 0) {
    char *v = NULL;
    if (db_take_string(ctx, "database", key, 32, &v) != 0) { free(v); return -1; }
    if (strcmp(v, "sqlite3") != 0 && strcmp(v, "postgresql") != 0) {
      db_cfg_error(ctx, "database: unknown driver '%.32s' (expected sqlite3 or postgresql)", v);
      free(v);
      return -1;
    }
    free(db->driver);
    db->driver = v;
    return 0;
  }
  if (strcmp(key, "database-file") == 0) return db_take_string(ctx, "database", key, KARIDNS_DB_PATH_MAX, &db->database_file);
  if (strcmp(key, "conninfo-file") == 0) return db_take_string(ctx, "database", key, KARIDNS_DB_PATH_MAX, &db->conninfo_file);
  if (strcmp(key, "schema") == 0) return db_take_string(ctx, "database", key, KARIDNS_DB_PATH_MAX, &db->schema);
  if (strcmp(key, "loader-user") == 0) return db_take_string(ctx, "database", key, 255, &db->loader_user);
  if (strcmp(key, "loader-group") == 0) return db_take_string(ctx, "database", key, 255, &db->loader_group);
  if (strcmp(key, "loader-path") == 0) return db_take_string(ctx, "database", key, KARIDNS_DB_PATH_MAX, &db->loader_path);
  if (strcmp(key, "server-id") == 0) return db_take_string(ctx, "database", key, 64, &db->server_id);
  if (strcmp(key, "auto-reload") == 0) return parse_bool_statement(ctx, NULL, key, &db->auto_reload);
  if (strcmp(key, "poll-interval") == 0) {
    if (db_take_uint(ctx, key, false, KARIDNS_DB_POLL_MIN, KARIDNS_DB_POLL_MAX, &u) != 0) return -1;
    db->poll_interval = (uint32_t)u;
    return 0;
  }
  if (strcmp(key, "coalesce") == 0) {
    if (db_take_uint(ctx, key, false, 0, KARIDNS_DB_COALESCE_MAX, &u) != 0) return -1;
    db->coalesce_ms = (uint32_t)u;
    return 0;
  }
  if (strcmp(key, "default-ttl") == 0) {
    if (db_take_uint(ctx, key, false, 1, KARIDNS_DB_TTL_MAX, &u) != 0) return -1;
    db->default_ttl = (uint32_t)u;
    return 0;
  }
  if (strcmp(key, "bulk-threshold") == 0) {
    if (db_take_uint(ctx, key, false, 0, 100, &u) != 0) return -1;
    db->bulk_threshold = (uint32_t)u;
    return 0;
  }
  if (strcmp(key, "max-zone-records") == 0)
    return db_take_uint(ctx, key, false, 2, KARIDNS_DB_MAX_ZONE_RECORDS_MAX, &db->max_zone_records);
  if (strcmp(key, "max-zone-bytes") == 0)
    return db_take_uint(ctx, key, true, KARIDNS_DB_MAX_ZONE_BYTES_MIN, KARIDNS_DB_MAX_ZONE_BYTES_MAX,
                        &db->max_zone_bytes);
  if (strcmp(key, "db-reload-timeout") == 0) {
    if (db_take_uint(ctx, key, false, 1, KARIDNS_DB_RELOAD_TIMEOUT_MAX, &u) != 0) return -1;
    db->db_reload_timeout = (uint32_t)u;
    return 0;
  }
  if (strcmp(key, "ingest-threads") == 0) {
    if (db_take_uint(ctx, key, false, 1, KARIDNS_DB_THREADS_MAX, &u) != 0) return -1;
    db->ingest_threads = (uint32_t)u;
    return 0;
  }
  if (strcmp(key, "loader-threads") == 0) {
    if (db_take_uint(ctx, key, false, 1, KARIDNS_DB_THREADS_MAX, &u) != 0) return -1;
    db->loader_threads = (uint32_t)u;
    return 0;
  }
  if (strcmp(key, "acl-ceiling") == 0) {
    /* addresses and "key" entries like allow-transfer (see zone_transfer_acl_allows(), dns_tsig_acl.c) */
    free_str_list(db->acl_ceiling, db->acl_ceiling_count);
    free(db->acl_ceiling_parsed);
    free_str_list(db->acl_ceiling_keys, db->acl_ceiling_keys_count);
    db->acl_ceiling = NULL;
    db->acl_ceiling_parsed = NULL;
    db->acl_ceiling_keys = NULL;
    db->acl_ceiling_count = db->acl_ceiling_keys_count = 0;
    return parse_acl_list(ctx, &db->acl_ceiling, &db->acl_ceiling_count, ACL_KEY_AS_TSIG_FIELD,
                          &db->acl_ceiling_keys, &db->acl_ceiling_keys_count);
  }
  if (strcmp(key, "acl-ceiling-match") == 0) {
    /* B7b: with both addresses and keys in acl-ceiling, "any" (default) lets a client in by either, "all" needs both */
    char *v = NULL;
    if (db_take_string(ctx, "database", key, 8, &v) != 0) { free(v); return -1; }
    uint8_t m = strcasecmp(v, "any") == 0 ? ACL_MATCH_ANY : strcasecmp(v, "all") == 0 ? ACL_MATCH_ALL : ACL_MATCH_DEFAULT;
    if (m == ACL_MATCH_DEFAULT) report_bad_value(ctx, NULL, key, v, "any or all");
    free(v);
    if (m == ACL_MATCH_DEFAULT) return -1;
    db->acl_ceiling_match = m;
    return 0;
  }
  if (strcmp(key, "alias-resolver") == 0) {
    free_str_list(db->alias_resolver, db->alias_resolver_count);
    db->alias_resolver = NULL;
    db->alias_resolver_count = 0;
    if (parse_string_list(ctx, &db->alias_resolver, &db->alias_resolver_count) != 0) return -1;
    for (int i = 0; i < db->alias_resolver_count; i++) {
      struct in_addr a4;
      struct in6_addr a6;
      if (inet_pton(AF_INET, db->alias_resolver[i], &a4) != 1 && inet_pton(AF_INET6, db->alias_resolver[i], &a6) != 1) {
        db_cfg_error(ctx, "database: alias-resolver entry '%.64s' is not an IP address", db->alias_resolver[i]);
        return -1;
      }
    }
    return 0;
  }
  db_cfg_error(ctx, "database: unknown option '%.64s'", key);
  return -1;
}

static int parse_database_block(token_ctx_t *ctx, server_config_t *config) {
  database_config_t *db = &config->database;
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_LBRACE) { free_token(&tok); return -1; }
  free_token(&tok);
  if (db->enabled) {
    db_cfg_error(ctx, "database: the block is given twice");
    return -1;
  }
  db->enabled = true;
  db->poll_interval = 2;
  db->coalesce_ms = 1000;
  db->default_ttl = 3600;
  db->bulk_threshold = 25;
  db->max_zone_records = KARIDNS_DB_MAX_ZONE_RECORDS_DEFAULT;
  db->max_zone_bytes = KARIDNS_DB_MAX_ZONE_BYTES_DEFAULT;
  db->db_reload_timeout = 30;
  db->ingest_threads = 1;
  db->loader_threads = 1;
  while (1) {
    tok = get_next_token(ctx);
    if (tok.type == TOKEN_RBRACE) { free_token(&tok); break; }
    if (tok.type != TOKEN_STRING) { free_token(&tok); return -1; }
    char *key = tok.value;
    tok.value = NULL;
    free_token(&tok);
    int rc = parse_database_option(ctx, db, key);
    free(key);
    if (rc != 0) return -1;
  }
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) { free_token(&tok); return -1; }
  free_token(&tok);
  return 0;
}

/* view { database-file "..."; database-schema "..."; database none; } */
static int parse_view_database_option(token_ctx_t *ctx, view_config_t *view, const char *key) {
  if (strcmp(key, "database-file") == 0) return db_take_string(ctx, view->name, key, KARIDNS_DB_PATH_MAX, &view->database_file);
  if (strcmp(key, "database-schema") == 0) return db_take_string(ctx, view->name, key, KARIDNS_DB_PATH_MAX, &view->database_schema);
  /* "database none;" */
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_STRING || !tok.value) { free_token(&tok); return -1; }
  if (strcmp(tok.value, "none") != 0) {
    db_cfg_error(ctx, "view '%s': invalid database value '%.32s' (expected none)", view->name, tok.value);
    free_token(&tok);
    return -1;
  }
  free_token(&tok);
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) { free_token(&tok); return -1; }
  free_token(&tok);
  view->database_none = true;
  return 0;
}

/* The rules that need the whole configuration (design 7.1): required fields per driver, driver / view option
 * consistency, view options without a database block. */
static int validate_database_config(token_ctx_t *ctx, server_config_t *config) {
  const database_config_t *db = &config->database;
  bool sqlite = db->enabled && db->driver && strcmp(db->driver, "sqlite3") == 0;
  bool pg = db->enabled && db->driver && strcmp(db->driver, "postgresql") == 0;
  bool need_global = false;
  unsigned db_views = 0;
  for (const view_config_t *v = config->views; v; v = v->next) {
    if (!v->database_none) db_views++;
    if ((v->database_file || v->database_schema || v->database_none) && !db->enabled) {
      db_cfg_error(ctx, "view '%s': database options need an options { database { ... }; } block", v->name);
      return -1;
    }
    if (v->database_none && (v->database_file || v->database_schema)) {
      db_cfg_error(ctx, "view '%s': \"database none;\" cannot be combined with database-file or database-schema", v->name);
      return -1;
    }
    if (pg && v->database_file) {
      db_cfg_error(ctx, "view '%s': database-file is for driver sqlite3 (this configuration uses postgresql)", v->name);
      return -1;
    }
    if (sqlite && v->database_schema) {
      db_cfg_error(ctx, "view '%s': database-schema is for driver postgresql (this configuration uses sqlite3)", v->name);
      return -1;
    }
    if (!v->database_none && !v->database_file && !v->database_schema) need_global = true;
  }
  if (!db->enabled) return 0;
  if (db_views > KARIDNS_DB_MAX_VIEWS) {
    /* the CONFIG message of the loader link lists every view that takes DB zones (dns_db_stream.h, KDB_MAX_CONFIG_VIEWS):
     * with more it cannot be sent and the loader would be restarted forever */
    db_cfg_error(ctx, "database: %u views take DB zones, at most %d are supported (mark the others with "
                      "\"database none;\")", db_views, KARIDNS_DB_MAX_VIEWS);
    return -1;
  }
  if (!db->driver) {
    db_cfg_error(ctx, "database: 'driver' is required (sqlite3 or postgresql)");
    return -1;
  }
  if (sqlite) {
    if (db->conninfo_file || db->schema) {
      db_cfg_error(ctx, "database: %s is for driver postgresql (this configuration uses sqlite3)",
                   db->conninfo_file ? "conninfo-file" : "schema");
      return -1;
    }
    if (!db->database_file && need_global) {
      db_cfg_error(ctx, "database: driver sqlite3 needs 'database-file' (a view without its own database-file or "
                        "\"database none;\" uses it)");
      return -1;
    }
  } else if (pg) {
    if (db->database_file) {
      db_cfg_error(ctx, "database: database-file is for driver sqlite3 (this configuration uses postgresql)");
      return -1;
    }
    if (!db->conninfo_file) {
      db_cfg_error(ctx, "database: driver postgresql needs 'conninfo-file'");
      return -1;
    }
  }
  return 0;
}

/* notify <yes|no|explicit|primary-only|master-only>; of options, view and zone (BIND 9.20 ARM "notify": "notify ( explicit | master-only |
 * primary-only | <boolean> );").  A value of the wrong kind is an error naming the place. */
static int parse_notify_mode(token_ctx_t *ctx, const char *what, uint8_t *out) {
  char db[96];
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_STRING || !tok.value) {
    conf_error(ctx, what, "expected yes, no, explicit or primary-only but found %s", tok_desc(&tok, db, sizeof(db)));
    free_token(&tok);
    return -1;
  }
  bool b;
  notify_mode_t m;
  if (strcasecmp(tok.value, "explicit") == 0) m = NOTIFY_MODE_EXPLICIT;
  else if (strcasecmp(tok.value, "primary-only") == 0 || strcasecmp(tok.value, "master-only") == 0) m = NOTIFY_MODE_PRIMARY_ONLY;
  else if (parse_config_bool(tok.value, &b)) m = b ? NOTIFY_MODE_YES : NOTIFY_MODE_NO;
  else {
    conf_error(ctx, what, "invalid value '%.64s' (expected yes, no, explicit, primary-only or master-only)", tok.value);
    free_token(&tok);
    return -1;
  }
  free_token(&tok);
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) {
    conf_error(ctx, what, "expected ';' after the value but found %s", tok_desc(&tok, db, sizeof(db)));
    free_token(&tok);
    return -1;
  }
  free_token(&tok);
  *out = (uint8_t)m;
  return 0;
}

/* x->masters_parsed (CIDR form of the addresses, for the "NOTIFY only from a primary" check).  0, or -1 when out of memory. */
static int masters_build_parsed(zone_ext_t *x) {
  free(x->masters_parsed);
  x->masters_parsed = NULL;
  if (x->masters_count <= 0 || !x->masters) return 0;
  x->masters_parsed = calloc((size_t)x->masters_count, sizeof(cidr_entry_t));
  if (!x->masters_parsed) return -1;
  for (int i = 0; i < x->masters_count; i++)
    if (x->masters[i].ip) cidr_entry_parse(&x->masters_parsed[i], x->masters[i].ip);
  return 0;
}

/* A semantic error of an also-notify statement or a remote-servers list (found after the whole configuration was read, so the place is the
 * "file:line" the element was written at, kept in notify_target_t.where). */
static void notify_cfg_error(token_ctx_t *ctx, const char *where, const char *what, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));
static void notify_cfg_error(token_ctx_t *ctx, const char *where, const char *what, const char *fmt, ...) {
  char msg[400];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);
  syslog(LOG_ERR, "[Config] %s%s%s: %s", where ? where : "", where ? ": " : "", what, msg);
  fprintf(stderr, "[ERROR] %s%s%s: %s\n", where ? where : "", where ? ": " : "", what, msg);
  if (ctx) ctx->error_occurred = true;
}

/* Expand the list names of src[0..n) into addresses appended to *out (BIND 9.20 ARM "remote-servers": a list may include other lists).
 * A `key` written on a list name is the key of those of its addresses that have none of their own; the `port` of a list that is named inside
 * another is the default of its addresses that have none (inherit_port: the port of the enclosing statement).  Every key must be defined in a
 * key { } block (RFC 8945 needs the secret to sign).  -1 with a message on an unknown name, an undefined key, a list that includes
 * itself (nesting deeper than KARIDNS_REMOTE_LIST_DEPTH) or more than KARIDNS_ALSO_NOTIFY_MAX addresses. */
static int expand_targets(token_ctx_t *ctx, const server_config_t *cfg, const char *what, const notify_target_t *src, int n,
                          const char *inherit_key, int inherit_port, int depth, notify_target_t **out, int *outn) {
  for (int i = 0; i < n; i++) {
    const notify_target_t *s = &src[i];
    const char *key = s->key ? s->key : inherit_key;
    if (s->key && !key_is_defined(ctx, cfg, s->key)) {
      notify_cfg_error(ctx, s->where, what, "key '%.64s' is not defined in any key {} block", s->key);
      return -1;
    }
    if (s->list) {
      const remote_list_t *l = cfg->remote_lists;
      while (l && strcasecmp(l->name, s->list) != 0) l = l->next;
      if (!l) {
        /* "192.0.2.1:53" was kept as an address string before and never worked; say how to write the port */
        const char *colon = strrchr(s->list, ':');
        bool ip_port = colon && colon != s->list && colon[1] && strspn(colon + 1, "0123456789") == strlen(colon + 1);
        notify_cfg_error(ctx, s->where, what, "'%.64s' is neither an IP address nor a remote-servers / primaries / masters list defined in this configuration%s",
                         s->list, ip_port ? " (write the port as '<address> port <n>')" : "");
        return -1;
      }
      if (depth + 1 > KARIDNS_REMOTE_LIST_DEPTH) {
        notify_cfg_error(ctx, s->where, what, "remote-servers lists are nested more than %d deep (does list '%.64s' include itself?)",
                         KARIDNS_REMOTE_LIST_DEPTH, s->list);
        return -1;
      }
      if (expand_targets(ctx, cfg, what, l->items, l->count, key, s->port ? s->port : inherit_port, depth + 1, out, outn) != 0) return -1;
      continue;
    }
    if (*outn >= KARIDNS_ALSO_NOTIFY_MAX) {
      notify_cfg_error(ctx, s->where, what, "more than %d addresses after the lists are expanded", KARIDNS_ALSO_NOTIFY_MAX);
      return -1;
    }
    notify_target_t *nl = realloc(*out, sizeof(notify_target_t) * (size_t)(*outn + 1));
    if (!nl) {
      if (ctx) ctx->error_occurred = true;
      return -1;
    }
    *out = nl;
    notify_target_t *t = &nl[*outn];
    memset(t, 0, sizeof(*t));
    (*outn)++;
    t->ip = strdup(s->ip);
    t->port = s->port ? s->port : (inherit_port ? inherit_port : 53);   /* the list's port, else the enclosing list's (BIND getipandkeylist()), else 53 */
    if (key) t->key = strdup(key);
    memcpy(t->src_set, s->src_set, sizeof(t->src_set));
    memcpy(t->src, s->src, sizeof(t->src));
    if (s->src_loc) t->src_loc = strdup(s->src_loc);
    if (!t->ip || (key && !t->key) || (s->src_loc && !t->src_loc)) {
      if (ctx) ctx->error_occurred = true;
      return -1;
    }
  }
  return 0;
}

/* Replace the statement *list by its expansion (every element an address, no `where`, no `list`) */
static int resolve_notify_field(token_ctx_t *ctx, const server_config_t *cfg, const char *what, notify_target_t **list, int *count) {
  if (*count == 0) return 0;
  notify_target_t *out = NULL;
  int outn = 0;
  if (expand_targets(ctx, cfg, what, *list, *count, NULL, 0, 0, &out, &outn) != 0) {
    notify_targets_free(out, outn);
    return -1;
  }
  notify_targets_free(*list, *count);
  *list = out;
  *count = outn;
  return 0;
}

/* After the whole configuration is read: check every remote-servers list, and expand the lists named in also-notify of options, views
 * and zones, so that the server only ever sees addresses.  Also the "zone replaces the view's, the view's replaces options'" rule needs
 * nothing here: it is applied when a NOTIFY is sent (also_notify_effective()). */
static int resolve_all_notify_targets(token_ctx_t *ctx, server_config_t *config) {
  char what[DNS_NAME_TEXT_SIZE + 128];
  for (const remote_list_t *l = config->remote_lists; l; l = l->next) {
    snprintf(what, sizeof(what), "remote-servers '%.64s'", l->name);
    notify_target_t *tmp = NULL;
    int tn = 0;
    int rc = expand_targets(ctx, config, what, l->items, l->count, NULL, 0, 0, &tmp, &tn);
    notify_targets_free(tmp, tn);
    if (rc != 0) return -1;
  }
  if (resolve_notify_field(ctx, config, "options also-notify", &config->also_notify, &config->also_notify_count) != 0) return -1;
  for (view_config_t *v = config->views; v; v = v->next) {
    ctx->scope_keys = v->keys;
    snprintf(what, sizeof(what), "view '%.64s' also-notify", v->name);
    if (resolve_notify_field(ctx, config, what, &v->also_notify, &v->also_notify_count) != 0) return -1;
    for (zone_config_t *z = v->zones; z; z = z->next) {
      zone_ext_t *zx = z->ext;
      if (!zx) continue;
      snprintf(what, sizeof(what), "zone '%.255s' also-notify", z->domain);
      if (resolve_notify_field(ctx, config, what, &zx->also_notify, &zx->also_notify_count) != 0) return -1;
      if (zx->masters_count > 0) {
        /* primaries / masters of the zone: the same lists, the same checks; masters_parsed is built from the expanded addresses */
        snprintf(what, sizeof(what), "zone '%.255s' primaries", z->domain);
        if (resolve_notify_field(ctx, config, what, &zx->masters, &zx->masters_count) != 0) return -1;
        if (masters_build_parsed(zx) != 0) {
          if (ctx) ctx->error_occurred = true;
          return -1;
        }
      }
    }
    ctx->scope_keys = NULL;
  }
  return 0;
}

notify_mode_t notify_mode_effective(const server_config_t *cfg, const zone_config_t *zone, const char *view_name) {
  const zone_ext_t *zx = zext(zone);
  if (zx->notify_mode) return (notify_mode_t)zx->notify_mode;
  if (cfg) {
    if (view_name && view_name[0])
      for (const view_config_t *v = cfg->views; v; v = v->next)
        if (strcasecmp(v->name, view_name) == 0) {
          if (v->notify_mode) return (notify_mode_t)v->notify_mode;
          break;
        }
    if (cfg->notify_mode) return (notify_mode_t)cfg->notify_mode;
  }
  return NOTIFY_MODE_YES;
}

int also_notify_effective(const server_config_t *cfg, const zone_config_t *zone, const char *view_name,
                          const notify_target_t **out) {
  const zone_ext_t *zx = zext(zone);
  if (zx->also_notify_set) {
    *out = zx->also_notify;
    return zx->also_notify_count;
  }
  if (cfg) {
    if (view_name && view_name[0]) {
      for (const view_config_t *v = cfg->views; v; v = v->next)
        if (strcasecmp(v->name, view_name) == 0) {
          if (v->also_notify_set) {
            *out = v->also_notify;
            return v->also_notify_count;
          }
          break;
        }
    }
    *out = cfg->also_notify;
    return cfg->also_notify_count;
  }
  *out = NULL;
  return 0;
}

/* ---- the source addresses of the configuration (batch 4) ---- */

static const char *const k_xsrc_names[XSRC_N] = {"notify-source", "notify-source-v6", "transfer-source", "transfer-source-v6"};

static int xs_add(token_ctx_t *ctx, server_config_t *cfg, int family, const uint8_t addr[16], bool notify, bool xfer, const char *loc,
                  const char *what) {
  size_t alen = family == AF_INET ? 4 : 16;
  for (int i = 0; i < cfg->xfr_source_count; i++) {
    xfr_source_t *s = &cfg->xfr_sources[i];
    if (s->family == family && memcmp(s->addr, addr, alen) == 0) {
      s->notify |= notify;
      s->xfer |= xfer;
      return 0;
    }
  }
  if (cfg->xfr_source_count >= KARIDNS_XFR_SOURCES_MAX) {
    syslog(LOG_ERR, "[Config] %s: %s: more than %d distinct source addresses", loc && loc[0] ? loc : "configuration", what,
           KARIDNS_XFR_SOURCES_MAX);
    fprintf(stderr, "[ERROR] %s: %s: more than %d distinct source addresses\n", loc && loc[0] ? loc : "configuration", what,
            KARIDNS_XFR_SOURCES_MAX);
    if (ctx) ctx->error_occurred = true;
    return -1;
  }
  xfr_source_t *n = realloc(cfg->xfr_sources, sizeof(*n) * (size_t)(cfg->xfr_source_count + 1));
  if (!n) {
    if (ctx) ctx->error_occurred = true;
    return -1;
  }
  cfg->xfr_sources = n;
  xfr_source_t *s = &n[cfg->xfr_source_count++];
  memset(s, 0, sizeof(*s));
  s->family = (uint8_t)family;
  memcpy(s->addr, addr, alen);
  s->notify = notify;
  s->xfer = xfer;
  inet_ntop(family, addr, s->text, sizeof(s->text));
  snprintf(s->loc, sizeof(s->loc), "%s", loc ? loc : "");
  snprintf(s->what, sizeof(s->what), "%s", what);
  return 0;
}

static int xs_from_xo(token_ctx_t *ctx, server_config_t *cfg, const xfr_opts_t *xo) {
  if (!xo) return 0;
  for (int s = 0; s < XSRC_N; s++) {
    if (xo->src[s].state != 1) continue;
    bool v6 = s == XSRC_NOTIFY6 || s == XSRC_XFER6;
    if (xs_add(ctx, cfg, v6 ? AF_INET6 : AF_INET, xo->src[s].addr, s < XSRC_XFER4, s >= XSRC_XFER4, xo->src[s].loc, k_xsrc_names[s]) != 0)
      return -1;
  }
  return 0;
}

static int xs_from_targets(token_ctx_t *ctx, server_config_t *cfg, const notify_target_t *t, int n, bool notify) {
  for (int i = 0; i < n; i++)
    for (int v = 0; v < 2; v++) {
      if (!t[i].src_set[v]) continue;
      if (xs_add(ctx, cfg, v ? AF_INET6 : AF_INET, t[i].src[v], notify, !notify, t[i].src_loc,
                 notify ? (v ? "also-notify source-v6" : "also-notify source") : (v ? "primaries source-v6" : "primaries source")) != 0)
        return -1;
    }
  return 0;
}

int config_collect_xfr_sources(token_ctx_t *ctx, server_config_t *cfg) {
  free(cfg->xfr_sources);
  cfg->xfr_sources = NULL;
  cfg->xfr_source_count = 0;
  if (xs_from_xo(ctx, cfg, &cfg->xo) != 0 || xs_from_targets(ctx, cfg, cfg->also_notify, cfg->also_notify_count, true) != 0) return -1;
  for (const server_stmt_t *s = cfg->servers; s; s = s->next)
    if (xs_from_xo(ctx, cfg, &s->xo) != 0) return -1;
  for (const view_config_t *v = cfg->views; v; v = v->next) {
    for (const server_stmt_t *s = v->servers; s; s = s->next)
      if (xs_from_xo(ctx, cfg, &s->xo) != 0) return -1;
    if (xs_from_xo(ctx, cfg, &v->xo) != 0 || xs_from_targets(ctx, cfg, v->also_notify, v->also_notify_count, true) != 0) return -1;
    for (const zone_config_t *z = v->zones; z; z = z->next) {
      const zone_ext_t *x = z->ext;
      if (!x) continue;
      if (xs_from_xo(ctx, cfg, x->xo) != 0 || xs_from_targets(ctx, cfg, x->also_notify, x->also_notify_count, true) != 0 ||
          xs_from_targets(ctx, cfg, x->masters, x->masters_count, false) != 0)
        return -1;
    }
  }
  return 0;
}

static xfr_source_t g_startup_xfr_sources[KARIDNS_XFR_SOURCES_MAX];
static int g_startup_xfr_source_count;

void config_set_startup_xfr_sources(const server_config_t *cfg) {
  g_startup_xfr_source_count = 0;
  if (!cfg) return;
  for (int i = 0; i < cfg->xfr_source_count && i < KARIDNS_XFR_SOURCES_MAX; i++) g_startup_xfr_sources[g_startup_xfr_source_count++] = cfg->xfr_sources[i];
}

bool config_xfr_source_allowed(int family, const uint8_t addr[16], bool xfer) {
  size_t alen = family == AF_INET ? 4 : 16;
  for (int i = 0; i < g_startup_xfr_source_count; i++) {
    const xfr_source_t *s = &g_startup_xfr_sources[i];
    if (s->family == family && memcmp(s->addr, addr, alen) == 0) return xfer ? s->xfer : s->notify;
  }
  return false;
}

/* *path becomes "dir/path" when it is a relative path (an absolute one, "" and NULL stay).  false = out of memory. */
static bool dir_prefix_path(char **path, const char *dir) {
  if (!*path || (*path)[0] == '\0' || (*path)[0] == '/') return true;
  size_t n = strlen(dir) + 1 + strlen(*path) + 1;
  char *p = malloc(n);
  if (!p) return false;
  snprintf(p, n, "%s/%s", dir, *path);
  free(*path);
  *path = p;
  return true;
}

static bool dir_prefix_zones(zone_config_t *z, const char *dir) {
  for (; z; z = z->next)
    if (!dir_prefix_path(&z->file, dir)) return false;
  return true;
}

/* The directory the server was started in (config_set_base_cwd), NULL in karicheck and the tests. */
static char *g_conf_base_cwd = NULL;

void config_set_base_cwd(const char *cwd) {
  free(g_conf_base_cwd);
  g_conf_base_cwd = (cwd && cwd[0] == '/') ? strdup(cwd) : NULL;
}

/* *path becomes "<startup directory>/<path>" when a startup directory is known and *path is relative; an absolute path, "" and NULL stay.
 * The result must not be longer than maxlen bytes: a configuration error, never a truncated path.  -1 = error (reported, ctx marked). */
static int path_absolutize(token_ctx_t *ctx, char **path, const char *what, size_t maxlen) {
  if (!g_conf_base_cwd || !*path || (*path)[0] == '\0' || (*path)[0] == '/') return 0;
  size_t n = strlen(g_conf_base_cwd) + 1 + strlen(*path);
  if (n > maxlen) {
    conf_error(ctx, "options", "%s: the relative path '%.64s' is %zu bytes long once it is made absolute against the directory karidns was "
               "started in (at most %zu); use a shorter path", what, *path, n, maxlen);
    return -1;
  }
  char *p = malloc(n + 1);
  if (!p) {
    ctx->error_occurred = true;
    return -1;
  }
  snprintf(p, n + 1, "%s/%s", g_conf_base_cwd, *path);
  free(*path);
  *path = p;
  return 0;
}

/* options { directory } (BIND 9.20 ARM): the base of every relative path.  Decides which directory applies (the one the running server was
 * started with when config_pin_directory() was called, else the one written), keeps it in config->directory and makes the relative paths
 * of the configuration absolute-or-startup-relative by putting it in front: zone `file`, `pid-file`, the files of logging channels and the
 * database files (`include` statements were resolved against it while they were read).  The server chdir()s to the directory once at start-up,
 * which is what the UNIX socket paths of `control-channel` and `dnstap` rely on.
 * Everything downstream (the directory fd cache, the zone loader, the logging code) then sees ordinary paths and opens the directory
 * once, before the sandbox, like any other.  Without a directory nothing changes: relative paths are relative to the directory the
 * server was started in.
 * When the server told the parser where it was started (config_set_base_cwd), the paths that the loader child (started from "/") or a
 * reload in another working directory would not find are made absolute here, once: the directory itself, pid-file, loader-path and the database files that karidns-dbloader (started
 * from "/" too) opens.  UNIX socket paths and the files that go through the directory fd cache (which resolves relative names against the
 * startup directory fd, not the current directory) are left as they are. */
static int config_apply_directory(token_ctx_t *ctx, server_config_t *config) {
  char *written = ctx->dir_written ? strdup(ctx->dir_written) : NULL;
  char *eff = NULL;
  int rc = -1;
  if (ctx->dir_written && !written) goto oom;
  if (written && path_absolutize(ctx, &written, "options: directory", KARIDNS_DB_PATH_MAX) != 0) goto out;
  if (ctx->dir_pinned) {
    if (ctx->directory) {
      eff = strdup(ctx->directory);
      if (!eff) goto oom;
      if (path_absolutize(ctx, &eff, "options: directory", KARIDNS_DB_PATH_MAX) != 0) goto out;
    }
    bool same = written ? (eff && strcmp(written, eff) == 0) : eff == NULL;
    if (!same) {
      syslog(LOG_WARNING, "[Config] options: directory %s%s%s differs from the directory the server was started with (%s%s%s); "
             "the running server keeps using the old one until it is restarted",
             written ? "'" : "", written ? written : "(not set)", written ? "'" : "", eff ? "'" : "", eff ? eff : "not set", eff ? "'" : "");
      fprintf(stderr, "[WARNING] options: directory %s%s%s differs from the directory the server was started with (%s%s%s); "
              "the running server keeps using the old one until it is restarted\n",
              written ? "'" : "", written ? written : "(not set)", written ? "'" : "", eff ? "'" : "", eff ? eff : "not set", eff ? "'" : "");
      config->directory_changed = true;
    }
    free(written);
  } else {
    bool seen_by_include = ctx->dir_written && ctx->directory && strcmp(ctx->dir_written, ctx->directory) == 0;
    if (ctx->dir_written && !seen_by_include && ctx->dir_rel_before > 0) {
      conf_error(ctx, "options", "directory: relative 'include' statements were read before this statement, which is not in the main "
                 "configuration file; write 'directory' in the main file (BIND applies it to every include)");
      goto out;
    }
    eff = written;
  }
  written = NULL;
  if (eff) {
    config->directory = strdup(eff);
    if (!config->directory) goto oom;
    bool ok = true;
    if (config->pid_file && strcmp(config->pid_file, "none") != 0) ok = ok && dir_prefix_path(&config->pid_file, eff);
    ok = ok && dir_prefix_zones(config->zones, eff);
    for (view_config_t *v = config->views; ok && v; v = v->next) {
      ok = dir_prefix_zones(v->zones, eff) && dir_prefix_path(&v->database_file, eff);
    }
    for (log_channel_t *c = config->logging.channels; ok && c; c = c->next)
      ok = dir_prefix_path(&c->file_path, eff);
    /* the control-channel and dnstap sockets are NOT prefixed: a UNIX socket path holds 103 bytes (sun_path), a deep directory would overflow
     * it, and the server chdir()s to the directory at start-up (and daemonize() no longer leaves it), so the relative name resolves there */
    ok = ok && dir_prefix_path(&config->database.database_file, eff) && dir_prefix_path(&config->database.conninfo_file, eff);
    if (!ok) goto oom;
  }
  /* what is still relative (no directory, or a relative directory without a startup directory) and is opened after daemonize() */
  if (config->pid_file && strcmp(config->pid_file, "none") != 0 &&
      path_absolutize(ctx, &config->pid_file, "pid-file", KARIDNS_DB_PATH_MAX) != 0) goto out;
  if (path_absolutize(ctx, &config->database.database_file, "database database-file", KARIDNS_DB_PATH_MAX) != 0 ||
      path_absolutize(ctx, &config->database.conninfo_file, "database conninfo-file", KARIDNS_DB_PATH_MAX) != 0 ||
      path_absolutize(ctx, &config->database.loader_path, "database loader-path", KARIDNS_DB_PATH_MAX) != 0) goto out;
  for (view_config_t *v = config->views; v; v = v->next)
    if (path_absolutize(ctx, &v->database_file, "view database-file", KARIDNS_DB_PATH_MAX) != 0) goto out;
  rc = 0;
  goto out;
oom:
  ctx->error_occurred = true;
out:
  free(written);
  free(eff);
  return rc;
}

/* ---- logging { } (BIND 9.20 ARM "logging Block Grammar"; lib/isccfg/namedconf.c channel_clauses, logfile_fields, parse_logfile(),
 * parse_logseverity(), parse_printtime(), parse_optional_facility(); lib/isccfg/check.c check_logging(); bin/named/logconf.c) ----
 *   channel <name> { ( file <path> [versions (<n>|unlimited)] [size <size>] [suffix (increment|timestamp)] | syslog [<facility>] | stderr | null );
 *                    [severity (critical|error|warning|notice|info|dynamic|debug [<n>])]; [print-time (<bool>|local|iso8601|iso8601-utc)];
 *                    [print-severity <bool>]; [print-category <bool>]; [buffered <bool>]; [max-qps <n>]; };       (max-qps is KariDNS's)
 *   category <name> { <channel>; ... };
 * Exactly one destination per channel, an unknown category or channel name is an error (check_logging()); an unknown statement is an error
 * with the place, as everywhere else in this parser.  What KariDNS does not do (buffered, a facility it does not know, a size without
 * versions) is accepted with a warning that says so. */

static const struct { const char *name; int facility; } k_log_facilities[] = {
  { "kern", LOG_KERN }, { "user", LOG_USER }, { "mail", LOG_MAIL }, { "daemon", LOG_DAEMON }, { "auth", LOG_AUTH },
  { "syslog", LOG_SYSLOG }, { "lpr", LOG_LPR },
#ifdef LOG_NEWS
  { "news", LOG_NEWS },
#endif
#ifdef LOG_UUCP
  { "uucp", LOG_UUCP },
#endif
#ifdef LOG_CRON
  { "cron", LOG_CRON },
#endif
#ifdef LOG_AUTHPRIV
  { "authpriv", LOG_AUTHPRIV },
#endif
#ifdef LOG_FTP
  { "ftp", LOG_FTP },
#endif
  { "local0", LOG_LOCAL0 }, { "local1", LOG_LOCAL1 }, { "local2", LOG_LOCAL2 }, { "local3", LOG_LOCAL3 },
  { "local4", LOG_LOCAL4 }, { "local5", LOG_LOCAL5 }, { "local6", LOG_LOCAL6 }, { "local7", LOG_LOCAL7 },
};

/* isc_syslog_facilityfromstring() (lib/isc/syslog.c): case-insensitive */
static bool log_facility_from_name(const char *s, int *out) {
  for (size_t i = 0; i < sizeof(k_log_facilities) / sizeof(k_log_facilities[0]); i++)
    if (strcasecmp(k_log_facilities[i].name, s) == 0) {
      *out = k_log_facilities[i].facility;
      return true;
    }
  return false;
}

/* the channels BIND creates itself (lib/isc/log.c isc_logconfig_create(), bin/named/log.c): a channel of the file with the same name
 * replaces the built-in one (isc_log_createchannel() prepends) */
static const char *const k_log_builtin_channels[] = { "default_syslog", "default_stderr", "default_debug", "null", NULL };

static bool log_channel_is_builtin(const char *name) {
  for (int i = 0; k_log_builtin_channels[i]; i++)
    if (strcmp(k_log_builtin_channels[i], name) == 0) return true;
  return false;
}

/* parse_sizeval() / parse_size(): digits with an optional k, m or g (bytes, KiB, ...); `unlimited` and `default` mean no limit (0).  KariDNS
 * has always accepted a trailing B after the unit ("10MB"), and still does.  A value BIND would not take (a sign, text) is an error. */
static bool log_parse_size(const char *s, uint64_t *out) {
  if (strcasecmp(s, "unlimited") == 0 || strcasecmp(s, "default") == 0) {
    *out = 0;
    return true;
  }
  if (!isdigit((unsigned char)s[0])) return false;
  char *end = NULL;
  errno = 0;
  unsigned long long v = strtoull(s, &end, 10);
  if (errno == ERANGE) return false;
  uint64_t unit = 1;
  if (*end) {
    switch (*end) {
      case 'k': case 'K': unit = 1024ULL; break;
      case 'm': case 'M': unit = 1024ULL * 1024; break;
      case 'g': case 'G': unit = 1024ULL * 1024 * 1024; break;
      default: return false;
    }
    end++;
    if (*end == 'b' || *end == 'B') end++;
    if (*end) return false;
  }
  if (v > UINT64_MAX / unit) return false;
  uint64_t r = v * unit;
  *out = r > (uint64_t)INT64_MAX ? 0 : r;   /* logconf.c: a size that does not fit off_t leaves the size unlimited */
  return true;
}

static bool log_parse_uint(const char *s, unsigned long max, unsigned long *out) {
  if (!isdigit((unsigned char)s[0])) return false;
  char *end = NULL;
  errno = 0;
  unsigned long v = strtoul(s, &end, 10);
  if (errno == ERANGE || *end || v > max) return false;
  *out = v;
  return true;
}

static int log_semi(token_ctx_t *ctx, const char *what, const char *after) {
  char db[96];
  conf_token_t t = get_next_token(ctx);
  if (t.type == TOKEN_SEMICOLON) {
    free_token(&t);
    return 0;
  }
  conf_error(ctx, what, "expected ';' after %s but found %s", after, tok_desc(&t, db, sizeof(db)));
  free_token(&t);
  return -1;
}

/* The next token, which must be a word or a string.  Returns its text (the caller frees it), or NULL after an error has been reported. */
static char *log_word(token_ctx_t *ctx, const char *what, const char *expect) {
  char db[96];
  conf_token_t t = get_next_token(ctx);
  if (t.type != TOKEN_STRING || !t.value) {
    conf_error(ctx, what, "expected %s but found %s", expect, tok_desc(&t, db, sizeof(db)));
    free_token(&t);
    return NULL;
  }
  char *v = t.value;
  t.value = NULL;
  return v;
}

typedef struct {
  bool dest, severity, print_time, print_category, print_severity, buffered, max_qps;
} log_chan_seen_t;

static void log_dup_clause(token_ctx_t *ctx, const char *what, const char *key) {
  conf_error(ctx, what, "'%s' is given twice", key);
}

/* `file <path> [versions ..] [size ..] [suffix ..];` after the word `file` (parse_logfile(): the options come in any order, each once) */
static int log_channel_file(token_ctx_t *ctx, log_channel_t *ch, const char *what) {
  char *path = log_word(ctx, what, "a file name");
  if (!path) return -1;
  if (!path[0]) {
    conf_error(ctx, what, "file: the file name is empty");
    free(path);
    return -1;
  }
  free(ch->file_path);
  ch->file_path = path;
  ch->dest = LOGDEST_FILE;
  bool got_versions = false, got_size = false, got_suffix = false;
  for (;;) {
    conf_token_t t = get_next_token(ctx);
    if (t.type == TOKEN_SEMICOLON) {
      free_token(&t);
      if (ch->size_limit > 0 && ch->versions == LOG_VERSIONS_UNSET && !ch->suffix_timestamp) {
        char loc[300];
        ctx_location(ctx, loc, sizeof(loc));
        conf_warn_loc(loc, what, "size without versions: when the file is full no more lines are written to it, as in BIND (earlier KariDNS "
                      "versions truncated it); add 'versions 0' to truncate it or 'versions <n>' to keep <n> old files");
      }
      return 0;
    }
    char db[96];
    if (t.type != TOKEN_STRING || !t.value || t.is_quoted) {
      conf_error(ctx, what, "file: expected versions, size, suffix or ';' but found %s", tok_desc(&t, db, sizeof(db)));
      free_token(&t);
      return -1;
    }
    char key[16];
    snprintf(key, sizeof(key), "%.15s", t.value);
    free_token(&t);
    bool *got = strcasecmp(key, "versions") == 0 ? &got_versions : strcasecmp(key, "size") == 0 ? &got_size
              : strcasecmp(key, "suffix") == 0 ? &got_suffix : NULL;
    if (!got) {
      conf_error(ctx, what, "file: unknown option '%.64s' (expected versions, size or suffix)", key);
      return -1;
    }
    if (*got) {
      log_dup_clause(ctx, what, key);
      return -1;
    }
    *got = true;
    char *val = log_word(ctx, what, "a value");
    if (!val) return -1;
    bool ok = true;
    if (strcasecmp(key, "versions") == 0) {
      if (strcasecmp(val, "unlimited") == 0) {
        ch->versions = LOG_VERSIONS_UNLIMITED;
      } else {
        unsigned long n;
        ok = log_parse_uint(val, INT_MAX, &n);
        if (ok) ch->versions = (int)n;
      }
      if (!ok) conf_error(ctx, what, "file: invalid versions value '%.64s' (expected a number or unlimited)", val);
    } else if (strcasecmp(key, "size") == 0) {
      uint64_t sz;
      ok = log_parse_size(val, &sz);
      if (ok) ch->size_limit = (size_t)sz;
      else conf_error(ctx, what, "file: invalid size value '%.64s' (expected a number with an optional k, m or g, unlimited or default)", val);
    } else if (strcasecmp(val, "timestamp") == 0) {
      ch->suffix_timestamp = true;
    } else if (strcasecmp(val, "increment") == 0) {
      ch->suffix_timestamp = false;
    } else {
      ok = false;
      conf_error(ctx, what, "file: invalid suffix '%.64s' (expected increment or timestamp)", val);
    }
    free(val);
    if (!ok) return -1;
  }
}

/* One statement of a channel block; the key has been read.  Returns 0, or -1 after an error has been reported. */
static int log_channel_clause(token_ctx_t *ctx, log_channel_t *ch, const char *what, const char *key, log_chan_seen_t *seen) {
  char db[96];
  if (strcmp(key, "file") == 0 || strcmp(key, "syslog") == 0 || strcmp(key, "null") == 0 || strcmp(key, "stderr") == 0) {
    if (seen->dest) {
      conf_error(ctx, what, "exactly one of file, syslog, null, and stderr must be present");
      return -1;
    }
    seen->dest = true;
    if (strcmp(key, "file") == 0) return log_channel_file(ctx, ch, what);
    if (strcmp(key, "null") == 0) {
      ch->dest = LOGDEST_NULL;
      return log_semi(ctx, what, "null");
    }
    if (strcmp(key, "stderr") == 0) {
      ch->dest = LOGDEST_STDERR;
      return log_semi(ctx, what, "stderr");
    }
    ch->dest = LOGDEST_SYSLOG;
    ch->syslog_facility = LOG_DAEMON;
    conf_token_t t = get_next_token(ctx);
    if (t.type == TOKEN_SEMICOLON) {
      free_token(&t);
      return 0;
    }
    if (t.type != TOKEN_STRING || !t.value) {
      conf_error(ctx, what, "syslog: expected a facility or ';' but found %s", tok_desc(&t, db, sizeof(db)));
      free_token(&t);
      return -1;
    }
    int fac;
    if (log_facility_from_name(t.value, &fac)) {
      ch->syslog_facility = fac;
    } else {
      char loc[300];
      ctx_location(ctx, loc, sizeof(loc));
      conf_warn_loc(loc, what, "syslog: unknown facility '%.40s'; daemon is used (BIND does the same)", t.value);
    }
    free_token(&t);
    return log_semi(ctx, what, "the syslog facility");
  }
  if (strcmp(key, "severity") == 0) {
    if (seen->severity) { log_dup_clause(ctx, what, key); return -1; }
    seen->severity = true;
    char *v = log_word(ctx, what, "a severity");
    if (!v) return -1;
    static const struct { const char *name; int level; } names[] = {
      { "critical", LOG_LVL_CRITICAL }, { "error", LOG_LVL_ERROR }, { "warning", LOG_LVL_WARNING },
      { "notice", LOG_LVL_NOTICE }, { "info", LOG_LVL_INFO }, { "dynamic", LOG_LVL_DYNAMIC },
    };
    bool ok = false;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]) && !ok; i++)
      if (strcasecmp(v, names[i].name) == 0) {
        ch->level = names[i].level;
        ok = true;
      }
    if (!ok && strcasecmp(v, "debug") == 0) {
      /* parse_logseverity(): the level is optional and defaults to 1; `debug 0` is the dynamic level (logconf.c passes the number on) */
      conf_token_t t = get_next_token(ctx);
      if (t.type == TOKEN_SEMICOLON) {
        free_token(&t);
        ch->level = 1;
        free(v);
        return 0;
      }
      unsigned long n;
      if (t.type != TOKEN_STRING || !t.value || !log_parse_uint(t.value, INT_MAX, &n)) {
        conf_error(ctx, what, "severity: invalid debug level %s (expected a number)", tok_desc(&t, db, sizeof(db)));
        free_token(&t);
        free(v);
        return -1;
      }
      free_token(&t);
      ch->level = (int)n;
      ok = true;
    }
    if (!ok) {
      conf_error(ctx, what, "severity: invalid severity '%.64s' (expected critical, error, warning, notice, info, dynamic or debug [n])", v);
      free(v);
      return -1;
    }
    free(v);
    return log_semi(ctx, what, "the severity");
  }
  if (strcmp(key, "print-time") == 0) {
    if (seen->print_time) { log_dup_clause(ctx, what, key); return -1; }
    seen->print_time = true;
    char *v = log_word(ctx, what, "yes, no, local, iso8601 or iso8601-utc");
    if (!v) return -1;
    bool b, ok = true;
    if (strcasecmp(v, "local") == 0) ch->time_fmt = LOGTIME_LOCAL;
    else if (strcasecmp(v, "iso8601") == 0) ch->time_fmt = LOGTIME_ISO8601;
    else if (strcasecmp(v, "iso8601-utc") == 0) ch->time_fmt = LOGTIME_ISO8601_UTC;
    else if (parse_config_bool(v, &b)) ch->time_fmt = b ? LOGTIME_LOCAL : LOGTIME_NONE;
    else ok = false;
    if (!ok) conf_error(ctx, what, "print-time: invalid value '%.64s' (expected yes, no, local, iso8601 or iso8601-utc)", v);
    free(v);
    return ok ? log_semi(ctx, what, "print-time") : -1;
  }
  if (strcmp(key, "print-category") == 0 || strcmp(key, "print-severity") == 0 || strcmp(key, "buffered") == 0) {
    /* "print-category" / "print-severity" differ at index 6; "buffered" is the third */
    bool *dup = key[0] == 'b' ? &seen->buffered : key[6] == 'c' ? &seen->print_category : &seen->print_severity;
    bool *dst = key[0] == 'b' ? &ch->buffered : key[6] == 'c' ? &ch->print_category : &ch->print_severity;
    if (*dup) { log_dup_clause(ctx, what, key); return -1; }
    *dup = true;
    char *v = log_word(ctx, what, "yes or no");
    if (!v) return -1;
    bool ok = parse_config_bool(v, dst);
    if (!ok) conf_error(ctx, what, "%s: invalid value '%.64s' (expected yes or no)", key, v);
    free(v);
    if (!ok || log_semi(ctx, what, key) != 0) return -1;
    if (key[0] == 'b' && *dst) {
      char loc[300];
      ctx_location(ctx, loc, sizeof(loc));
      conf_warn_loc(loc, what, "buffered is accepted but has no effect: every line is written at once");
    }
    return 0;
  }
  if (strcmp(key, "max-qps") == 0) {
    if (seen->max_qps) { log_dup_clause(ctx, what, key); return -1; }
    seen->max_qps = true;
    char *v = log_word(ctx, what, "a number");
    if (!v) return -1;
    unsigned long n;
    bool ok = log_parse_uint(v, UINT32_MAX, &n);
    if (ok) {
      ch->max_qps = (uint32_t)n;
      ch->max_qps_specified = true;
    } else {
      conf_error(ctx, what, "max-qps: invalid value '%.64s' (expected a number)", v);
    }
    free(v);
    return ok ? log_semi(ctx, what, "max-qps") : -1;
  }
  conf_error(ctx, what, "unknown option '%.64s' (expected file, syslog, null, stderr, severity, print-time, print-severity, print-category, "
                        "buffered or max-qps)", key);
  return -1;
}

/* `channel <name> { ... };` after the word `channel` */
static int parse_log_channel(token_ctx_t *ctx, server_config_t *config) {
  char db[96], loc[300];
  logging_config_t *lc = &config->logging;
  char *name = log_word(ctx, "logging", "a channel name after 'channel'");
  if (!name) return -1;
  char what[160];
  snprintf(what, sizeof(what), "logging channel '%.64s'", name);
  conf_token_t t = get_next_token(ctx);
  if (t.type != TOKEN_LBRACE) {
    conf_error(ctx, what, "expected '{' but found %s", tok_desc(&t, db, sizeof(db)));
    free_token(&t);
    free(name);
    return -1;
  }
  free_token(&t);
  ctx_location(ctx, loc, sizeof(loc));
  log_channel_t *ch = calloc(1, sizeof(*ch));
  if (!ch) {
    ctx->error_occurred = true;
    free(name);
    return -1;
  }
  ch->name = name;
  ch->fd = -1;
  ch->level = LOG_LVL_INFO;
  ch->versions = LOG_VERSIONS_UNSET;
  ch->syslog_facility = LOG_DAEMON;
  ch->max_qps = config->query_log_max_qps;
  pthread_mutex_init(&ch->lock, NULL);
  bool defined_before = false;
  for (log_channel_t *o = lc->channels; o; o = o->next)
    if (o->name && strcmp(o->name, name) == 0) defined_before = true;
  if (defined_before)
    conf_warn_loc(loc, what, "the channel is defined twice; the later definition is used");
  else if (log_channel_is_builtin(name))
    conf_warn_loc(loc, what, "this replaces the built-in channel of that name");
  /* linked first: an error below leaves the channel for the cleanup of the configuration */
  ch->next = lc->channels;
  lc->channels = ch;
  log_chan_seen_t seen;
  memset(&seen, 0, sizeof(seen));
  for (;;) {
    t = get_next_token(ctx);
    if (t.type == TOKEN_RBRACE) {
      free_token(&t);
      break;
    }
    if (t.type != TOKEN_STRING || !t.value || t.is_quoted) {
      conf_error(ctx, what, "expected a channel option or '}' but found %s", tok_desc(&t, db, sizeof(db)));
      free_token(&t);
      return -1;
    }
    char key[40];
    snprintf(key, sizeof(key), "%.39s", t.value);
    free_token(&t);
    if (log_channel_clause(ctx, ch, what, key, &seen) != 0) return -1;
  }
  if (log_semi(ctx, what, "'}'") != 0) return -1;
  if (!seen.dest) {
    conf_error(ctx, what, "exactly one of file, syslog, null, and stderr must be present");
    return -1;
  }
  return 0;
}

typedef struct {
  int cat;
  char *name;
  char loc[200];
} log_pend_t;

/* `category <name> { <channel>; ... };` after the word `category`: the channel names are bound when the block is complete (a channel may
 * be defined after the category that uses it) */
static int parse_log_category(token_ctx_t *ctx, log_pend_t **pend, int *npend, int *cap) {
  char db[96], loc[300];
  char *cname = log_word(ctx, "logging", "a category name after 'category'");
  if (!cname) return -1;
  int cat = log_category_from_name(cname);
  char what[160];
  snprintf(what, sizeof(what), "logging category '%.64s'", cname);
  if (cat < 0) {
    conf_error(ctx, "logging", "undefined category: '%.64s'", cname);
    free(cname);
    return -1;
  }
  free(cname);
  conf_token_t t = get_next_token(ctx);
  if (t.type != TOKEN_LBRACE) {
    conf_error(ctx, what, "expected '{' but found %s", tok_desc(&t, db, sizeof(db)));
    free_token(&t);
    return -1;
  }
  free_token(&t);
  for (;;) {
    t = get_next_token(ctx);
    if (t.type == TOKEN_RBRACE) {
      free_token(&t);
      break;
    }
    if (t.type != TOKEN_STRING || !t.value) {
      conf_error(ctx, what, "expected a channel name or '}' but found %s", tok_desc(&t, db, sizeof(db)));
      free_token(&t);
      return -1;
    }
    ctx_location(ctx, loc, sizeof(loc));
    if (*npend == *cap) {
      int ncap = *cap ? *cap * 2 : 8;
      log_pend_t *np = realloc(*pend, (size_t)ncap * sizeof(**pend));
      if (!np) {
        ctx->error_occurred = true;
        free_token(&t);
        return -1;
      }
      *pend = np;
      *cap = ncap;
    }
    log_pend_t *p = &(*pend)[(*npend)++];
    p->cat = cat;
    p->name = t.value;
    t.value = NULL;
    snprintf(p->loc, sizeof(p->loc), "%s", loc);
    if (log_semi(ctx, what, "the channel name") != 0) return -1;
  }
  return log_semi(ctx, what, "'}'");
}

/* The channel of the file by that name (the newest definition), NULL if there is none */
static log_channel_t *log_find_channel(logging_config_t *lc, const char *name) {
  for (log_channel_t *c = lc->channels; c; c = c->next)
    if (c->name && strcmp(c->name, name) == 0) return c;
  return NULL;
}

static void logging_set_first_channel(logging_config_t *lc, int cat, char **name_slot, log_channel_t **chan_slot) {
  free(*name_slot);
  *name_slot = NULL;
  *chan_slot = NULL;
  if (lc->cat[cat].n > 0) {
    *name_slot = strdup(lc->cat[cat].name[0]);
    *chan_slot = log_find_channel(lc, lc->cat[cat].name[0]);
  }
}

/* After the block: bind the names (check_logging(): "undefined channel"), append them to their categories (BIND appends: two statements for
 * a category write to the channels of both) */
static int logging_bind_categories(token_ctx_t *ctx, server_config_t *config, log_pend_t *pend, int npend) {
  logging_config_t *lc = &config->logging;
  for (int i = 0; i < npend; i++) {
    log_pend_t *p = &pend[i];
    if (!log_find_channel(lc, p->name) && !log_channel_is_builtin(p->name)) {
      aml_report(ctx, p->loc, "logging", "undefined channel: '%.64s'", p->name);
      return -1;
    }
    log_cat_cfg_t *c = &lc->cat[p->cat];
    bool dup = false;
    for (int k = 0; k < c->n; k++)
      if (strcmp(c->name[k], p->name) == 0) dup = true;
    if (dup) {
      conf_warn_loc(p->loc, "logging", "category '%s': channel '%.64s' is listed twice; once is enough", log_category_names[p->cat], p->name);
      continue;
    }
    if (c->n >= LOG_ROUTE_MAX) {
      aml_report(ctx, p->loc, "logging", "category '%s': more than %d channels", log_category_names[p->cat], LOG_ROUTE_MAX);
      return -1;
    }
    c->name[c->n] = p->name;
    p->name = NULL;
    c->n++;
  }
  logging_set_first_channel(lc, LOGC_QUERIES, &lc->queries_channel_name, &lc->queries_channel);
  logging_set_first_channel(lc, LOGC_RESPONSES, &lc->responses_channel_name, &lc->responses_channel);
  return 0;
}

static int parse_logging_statement(token_ctx_t *ctx, server_config_t *config) {
  char db[96], loc[300];
  logging_config_t *lc = &config->logging;
  conf_token_t t = get_next_token(ctx);
  if (t.type != TOKEN_LBRACE) {
    conf_error(ctx, "logging", "expected '{' but found %s", tok_desc(&t, db, sizeof(db)));
    free_token(&t);
    return -1;
  }
  free_token(&t);
  ctx_location(ctx, loc, sizeof(loc));
  if (lc->seen)
    conf_warn_loc(loc, "logging", "a second logging statement: BIND accepts only one; the channels and categories of both are used");
  lc->seen = true;
  log_pend_t *pend = NULL;
  int npend = 0, cap = 0, rc = -1;
  for (;;) {
    t = get_next_token(ctx);
    if (t.type == TOKEN_RBRACE) {
      free_token(&t);
      break;
    }
    if (t.type != TOKEN_STRING || !t.value || t.is_quoted) {
      conf_error(ctx, "logging", "expected 'channel', 'category' or '}' but found %s", tok_desc(&t, db, sizeof(db)));
      free_token(&t);
      goto out;
    }
    char key[24];
    snprintf(key, sizeof(key), "%.23s", t.value);
    free_token(&t);
    if (strcmp(key, "channel") == 0) {
      if (parse_log_channel(ctx, config) != 0) goto out;
    } else if (strcmp(key, "category") == 0) {
      if (parse_log_category(ctx, &pend, &npend, &cap) != 0) goto out;
    } else {
      conf_error(ctx, "logging", "unknown statement '%.64s' (expected channel or category)", key);
      goto out;
    }
  }
  t = get_next_token(ctx);
  if (t.type != TOKEN_SEMICOLON) {
    conf_error(ctx, "logging", "expected ';' after '}' but found %s", tok_desc(&t, db, sizeof(db)));
    free_token(&t);
    goto out;
  }
  free_token(&t);
  rc = logging_bind_categories(ctx, config, pend, npend);
out:
  for (int i = 0; i < npend; i++) free(pend[i].name);
  free(pend);
  return rc;
}

/* The two switches the query path reads, once the whole file is known: the query log is on with `querylog yes`, off with `querylog no`, and
 * (not written) when `category queries` lists a channel -- BIND leaves it off until `rndc querylog`, KariDNS has always logged queries when
 * the category is configured; the response log (KariDNS's own category, also BIND 9.20's name) when `category responses` lists one */
static void logging_finish(server_config_t *config) {
  logging_config_t *lc = &config->logging;
  lc->queries_enabled = config->querylog_set ? config->querylog : lc->cat[LOGC_QUERIES].n > 0;
  lc->responses_enabled = lc->cat[LOGC_RESPONSES].n > 0;
}

/* ---- controls { } (BIND 9.20 ARM "controls Block Grammar"; lib/isccfg/namedconf.c inetcontrol_fields / controls_sockaddr_flags,
 * lib/isccfg/check.c check_controls()) ----
 *   controls { inet ( <ip_address> | * ) [ port ( <integer> | * ) ] allow { <address_match_element>; ... } [ keys { <string>; ... } ] [ read-only <boolean> ];
 *              unix <quoted_string> perm <integer> owner <integer> group <integer> [ keys { ... } ] [ read-only <boolean> ]; };
 * rndc speaks a protocol (ISCCC) KariDNS does not implement: karictl and control-channel are its control interface.  So an inet entry is
 * read and checked (the allow list, the keys, a duplicate address) and then ignored with a warning; `unix` is an error, as in BIND 9.20
 * ("unix control '%s': not supported"). */
static int parse_controls_inet(token_ctx_t *ctx, server_config_t *config) {
  char db[96], loc[300];
  const char *what = "controls";
  ctx_location(ctx, loc, sizeof(loc));
  char *addr = log_word(ctx, what, "an address or '*'");
  if (!addr) return -1;
  uint8_t ab[16];
  char norm[INET6_ADDRSTRLEN] = "";
  if (strcmp(addr, "*") == 0) {
    snprintf(norm, sizeof(norm), "0.0.0.0");   /* check.c: the wildcard is the IPv4 wildcard */
  } else if (inet_pton(AF_INET, addr, ab) == 1) {
    inet_ntop(AF_INET, ab, norm, sizeof(norm));
  } else if (inet_pton(AF_INET6, addr, ab) == 1) {
    inet_ntop(AF_INET6, ab, norm, sizeof(norm));
  } else {
    conf_error(ctx, what, "inet: '%.64s' is not an IPv4 or IPv6 address (or '*')", addr);
    free(addr);
    return -1;
  }
  int port = 0;
  conf_token_t t = get_next_token(ctx);
  if (t.type == TOKEN_STRING && t.value && !t.is_quoted && strcmp(t.value, "port") == 0) {
    free_token(&t);
    char *pv = log_word(ctx, what, "a port number or '*'");
    unsigned long p;
    if (!pv) { free(addr); return -1; }
    if (strcmp(pv, "*") == 0) {
      port = 0;
    } else if (log_parse_uint(pv, 65535, &p)) {
      port = (int)p;
    } else {
      conf_error(ctx, what, "inet %.64s: invalid port '%.64s'", addr, pv);
      free(pv);
      free(addr);
      return -1;
    }
    free(pv);
    t = get_next_token(ctx);
  }
  if (t.type != TOKEN_STRING || !t.value || t.is_quoted || strcmp(t.value, "allow") != 0) {
    conf_error(ctx, what, "inet %.64s: expected 'allow' but found %s", addr, tok_desc(&t, db, sizeof(db)));
    free_token(&t);
    free(addr);
    return -1;
  }
  free_token(&t);
  t = get_next_token(ctx);
  if (t.type != TOKEN_LBRACE) {
    conf_error(ctx, what, "inet %.64s: expected '{' after allow but found %s", addr, tok_desc(&t, db, sizeof(db)));
    free_token(&t);
    free(addr);
    return -1;
  }
  free_token(&t);
  char awhat[200];
  snprintf(awhat, sizeof(awhat), "controls inet %.64s allow", addr);
  aml_t *allow = parse_aml_body(ctx, awhat, 0);
  if (!allow) { free(addr); return -1; }
  /* BIND: the address and the port are the identity of the entry ("already defined") */
  for (int i = 0; i < config->controls_count; i++)
    if (strcmp(config->controls[i].addr, norm) == 0 && (config->controls[i].port ? config->controls[i].port : 953) == (port ? port : 953)) {
      conf_error(ctx, what, "inet control socket '%s#%d': already defined, previous definition: %s", norm, port ? port : 953,
                 config->controls[i].loc);
      aml_unref(allow);
      free(addr);
      return -1;
    }
  controls_inet_t *nc = realloc(config->controls, (size_t)(config->controls_count + 1) * sizeof(*nc));
  if (!nc) {
    ctx->error_occurred = true;
    aml_unref(allow);
    free(addr);
    return -1;
  }
  config->controls = nc;
  controls_inet_t *c = &nc[config->controls_count++];
  memset(c, 0, sizeof(*c));
  snprintf(c->loc, sizeof(c->loc), "%s", loc);
  snprintf(c->addr, sizeof(c->addr), "%s", norm);
  c->port = port;
  c->allow = allow;
  free(addr);
  /* [ keys { name; ... } ] [ read-only <bool> ] ; */
  bool got_keys = false, got_ro = false;
  for (;;) {
    t = get_next_token(ctx);
    if (t.type == TOKEN_SEMICOLON) {
      free_token(&t);
      break;
    }
    if (t.type != TOKEN_STRING || !t.value || t.is_quoted ||
        !((!got_keys && !got_ro && strcmp(t.value, "keys") == 0) || (!got_ro && strcmp(t.value, "read-only") == 0))) {
      conf_error(ctx, what, "inet %s: expected %s but found %s", c->addr, got_ro ? "';'" : got_keys ? "'read-only' or ';'" : "'keys', 'read-only' or ';'",
                 tok_desc(&t, db, sizeof(db)));
      free_token(&t);
      return -1;
    }
    bool is_keys = strcmp(t.value, "keys") == 0;
    free_token(&t);
    if (!is_keys) {
      got_ro = true;
      bool ro;
      char *v = log_word(ctx, what, "yes or no");
      if (!v) return -1;
      bool ok = parse_config_bool(v, &ro);
      if (!ok) conf_error(ctx, what, "inet %s: read-only: invalid value '%.64s' (expected yes or no)", c->addr, v);
      free(v);
      if (!ok) return -1;
      continue;
    }
    got_keys = true;
    t = get_next_token(ctx);
    if (t.type != TOKEN_LBRACE) {
      conf_error(ctx, what, "inet %s: expected '{' after keys but found %s", c->addr, tok_desc(&t, db, sizeof(db)));
      free_token(&t);
      return -1;
    }
    free_token(&t);
    for (;;) {
      t = get_next_token(ctx);
      if (t.type == TOKEN_RBRACE) {
        free_token(&t);
        break;
      }
      if (t.type != TOKEN_STRING || !t.value) {
        conf_error(ctx, what, "inet %s: expected a key name or '}' but found %s", c->addr, tok_desc(&t, db, sizeof(db)));
        free_token(&t);
        return -1;
      }
      char kloc[300];
      ctx_location(ctx, kloc, sizeof(kloc));
      char **nk = realloc(c->keys, (size_t)(c->nkeys + 1) * sizeof(*nk));
      if (nk) c->keys = nk;
      char **nl = nk ? realloc(c->key_loc, (size_t)(c->nkeys + 1) * sizeof(*nl)) : NULL;
      if (nl) c->key_loc = nl;
      if (!nk || !nl) {
        ctx->error_occurred = true;
        free_token(&t);
        return -1;
      }
      c->keys[c->nkeys] = t.value;
      t.value = NULL;
      c->key_loc[c->nkeys] = strdup(kloc);
      c->nkeys++;
      if (!c->key_loc[c->nkeys - 1] || log_semi(ctx, what, "the key name") != 0) {
        ctx->error_occurred = true;
        return -1;
      }
    }
  }
  conf_warn_loc(loc, what, "inet %s port %d: rndc is not supported; karictl and control-channel are the control interface of KariDNS. The "
                "entry is accepted and has no effect", c->addr, port ? port : 953);
  return 0;
}

static int parse_controls_statement(token_ctx_t *ctx, server_config_t *config) {
  char db[96];
  conf_token_t t = get_next_token(ctx);
  if (t.type != TOKEN_LBRACE) {
    conf_error(ctx, "controls", "expected '{' but found %s", tok_desc(&t, db, sizeof(db)));
    free_token(&t);
    return -1;
  }
  free_token(&t);
  for (;;) {
    t = get_next_token(ctx);
    if (t.type == TOKEN_RBRACE) {
      free_token(&t);
      break;
    }
    if (t.type != TOKEN_STRING || !t.value || t.is_quoted) {
      conf_error(ctx, "controls", "expected 'inet' or '}' but found %s", tok_desc(&t, db, sizeof(db)));
      free_token(&t);
      return -1;
    }
    bool is_inet = strcmp(t.value, "inet") == 0, is_unix = strcmp(t.value, "unix") == 0;
    char key[24];
    snprintf(key, sizeof(key), "%.23s", t.value);
    free_token(&t);
    if (is_inet) {
      if (parse_controls_inet(ctx, config) != 0) return -1;
    } else if (is_unix) {
      char *path = log_word(ctx, "controls", "a path");
      if (!path) return -1;
      conf_error(ctx, "controls", "unix control '%.200s': not supported (BIND 9.20 rejects it too)", path);
      free(path);
      return -1;
    } else {
      conf_error(ctx, "controls", "unknown statement '%.64s' (expected inet or unix)", key);
      return -1;
    }
  }
  return log_semi(ctx, "controls", "'}'");
}

/* check_controls(): the allow lists must name defined acls, the keys must be defined (top-level) keys.  Run when the file has been read. */
static int controls_resolve(token_ctx_t *ctx, server_config_t *cfg) {
  for (int i = 0; i < cfg->controls_count; i++) {
    controls_inet_t *c = &cfg->controls[i];
    char what[200];
    snprintf(what, sizeof(what), "controls inet %.64s allow", c->addr);
    if (aml_resolve(ctx, cfg, c->allow, what, false, 0) != 0) return -1;
    for (int k = 0; k < c->nkeys; k++) {
      bool found = false;
      for (const tsig_key_t *key = cfg->keys; key && !found; key = key->next)
        found = key->name && strcasecmp(key->name, c->keys[k]) == 0;
      if (!found) {
        aml_report(ctx, c->key_loc[k], "controls", "unknown key '%.64s'", c->keys[k]);
        return -1;
      }
    }
  }
  return 0;
}

static int parse_named_conf_internal(token_ctx_t *ctx, server_config_t *config) {
  int nr_rc = 0;
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
  memset(config->cookie_secrets, 0, sizeof(config->cookie_secrets));
  config->cookie_secret_count = 0;
  config->tcp_idle_timeout = 10000;
  config->tcp_initial_timeout = 10000;
  config->minimal_responses = false;
  config->minimal_any = false;
  config->minimal_any_ttl = 86400;
  config->wire_cache_max_records = 0;
  config->response_cache_size = 32 * 1024 * 1024;
  config->additional_from_auth = ADDITIONAL_AUTH_YES;
  config->notify_retry.retries = NOTIFY_RETRIES_DEFAULT;
  config->notify_retry.interval = NOTIFY_RETRY_INTERVAL_DEFAULT;
  config->notify_retry.backoff = NOTIFY_BACKOFF_FIXED;
  config->notify_retry.tcp_timeout = NOTIFY_TCP_TIMEOUT_DEFAULT;
  config->ixfr_history = IXFR_HISTORY_DEFAULT;
  config->max_zone_records = KARIDNS_DB_MAX_ZONE_RECORDS_DEFAULT;
  config->max_zone_bytes = KARIDNS_DB_MAX_ZONE_BYTES_DEFAULT;
  config->query_log_max_qps = 5000;
  config->querylog_set = false;
  config->querylog = false;
  config->query_log_buffer_size = 32768;
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
        char *key = tok.value;
        tok.value = NULL;
        free_token(&tok);
        if (strcmp(key, "port") == 0 || strcmp(key, "user") == 0 ||
            strcmp(key, "group") == 0 || strcmp(key, "pid-file") == 0 || strcmp(key, "directory") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) {
            free(key);
            free_token(&tok);
            return -1;
          }
          char *val = tok.value;
          tok.value = NULL;
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
            if (val[0] == '\0' || *endptr != '\0' || pval <= 0 || pval > 65535) {
              conf_error(ctx, "options", "port: invalid port '%.64s' (expected 1-65535)", val);
              free(key);
              free(val);
              return -1;
            }
            config->port = (int)pval;
            free(val);
          } else if (strcmp(key, "directory") == 0) {
            /* BIND 9.20 ARM: "This sets the working directory of the server"; every relative path of the configuration is relative to
             * it.  Applied when the whole configuration has been read (config_apply_directory), so the statement may come after the
             * paths it affects. */
            if (val[0] == '\0') {
              conf_error(ctx, "options", "directory: an empty directory name");
              free(key);
              free(val);
              return -1;
            }
            free(ctx->dir_written);
            ctx->dir_written = val;
            ctx->dir_rel_before = ctx->rel_includes;
            for (int fi = 1; fi <= ctx->depth && fi < MAX_INCLUDE_DEPTH; fi++)
              if (ctx->stack[fi].via_rel) ctx->dir_rel_before--;
          } else if (strcmp(key, "user") == 0) {
            if (config->user) free(config->user);
            config->user = val;
          } else if (strcmp(key, "group") == 0) {
            if (config->group) free(config->group);
            config->group = val;
          } else if (strcmp(key, "pid-file") == 0) {
            if (config->pid_file) free(config->pid_file);
            config->pid_file = val;
          }
        } else if (strcmp(key, "bind-address") == 0) {
          int bind_first_new = config->bind_address_count;
          tok = get_next_token(ctx);
          if (tok.type == TOKEN_LBRACE) {
            free_token(&tok);
            if (parse_string_list_inner(ctx, &config->bind_addresses,
                                  &config->bind_address_count) != 0) {
              free(key);
              return -1;
            }
            if (bind_address_check(ctx, config, bind_first_new) != 0) {
              free(key);
              return -1;
            }
          } else if (tok.type == TOKEN_STRING) {
            char *dup_addr = tok.value;
            tok.value = NULL;
            free_token(&tok);
            tok = get_next_token(ctx);
            if (tok.type != TOKEN_SEMICOLON) {
              free(key);
              free(dup_addr);
              free_token(&tok);
              return -1;
            }
            free_token(&tok);
            APPEND_STR(config->bind_addresses, config->bind_address_count, dup_addr);
            if (bind_address_check(ctx, config, bind_first_new) != 0) {
              free(key);
              return -1;
            }
          } else {
            free(key);
            free_token(&tok);
            return -1;
          }
        } else if (strcmp(key, "listen-on") == 0 || strcmp(key, "listen-on-v6") == 0) {
          if (parse_listen_statement(ctx, config, key[9] == '-') != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "blackhole") == 0) {
          aml_t *bh = parse_aml_statement(ctx, "options blackhole");
          if (!bh) {
            free(key);
            return -1;
          }
          aml_unref(config->blackhole);   /* a second blackhole statement replaces the first (like the other options) */
          config->blackhole = bh;
        } else if (strcmp(key, "rate-limit") == 0) {
          if (parse_rate_limit_config(ctx, &config->rrl) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "ecs-enable") == 0) {
          if (parse_bool_statement(ctx, NULL, key, &config->ecs_enable) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "ecs-trusted-resolvers") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_LBRACE) {
            free(key);
            free_token(&tok);
            return -1;
          }
          free_token(&tok);
          if (parse_string_list_inner(ctx, &config->ecs_trusted_resolvers,
                                      &config->ecs_trusted_resolvers_count) != 0) {
            free(key);
            return -1;
          }
          free(config->ecs_trusted_resolvers_parsed);
          config->ecs_trusted_resolvers_parsed = acl_list_parse(config->ecs_trusted_resolvers, config->ecs_trusted_resolvers_count);
        } else if (strcmp(key, "ecs-tags") == 0) {
          if (parse_ecs_tags_block(ctx, &config->ecs_tags, &config->ecs_tag_count) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "location-tags") == 0) {
          if (parse_ecs_tags_block(ctx, &config->location_tags, &config->location_tag_count) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "send-extended-errors") == 0) {
          if (parse_bool_statement(ctx, NULL, key, &config->send_extended_errors) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "serve-stale") == 0) {
          if (parse_bool_statement(ctx, NULL, key, &config->serve_stale) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "querylog") == 0) {
          /* BIND 9.20 options { querylog <boolean>; }: on or off for the `queries` category (see logging_finish()) */
          if (parse_bool_statement(ctx, NULL, key, &config->querylog) != 0) {
            free(key);
            return -1;
          }
          config->querylog_set = true;
        } else if (strcmp(key, "rfc10029-mqtype") == 0) {
          if (parse_bool_statement(ctx, NULL, key, &config->rfc10029_mqtype_enable) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "tcp-connection-reuse") == 0) {
          if (parse_bool_statement(ctx, NULL, key, &config->tcp_connection_reuse) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "tcp-idle-timeout") == 0 || strcmp(key, "tcp-initial-timeout") == 0) {
          /* BIND's unit (100 ms), or milliseconds with the suffix `ms` (parse_tcp_timeout()).  tcp-initial-timeout runs to the first
           * message, tcp-idle-timeout between messages (D-06, RFC 7766 §6.2.3).  `0ms` = the default of 10000 ms. */
          bool is_idle = strcmp(key, "tcp-idle-timeout") == 0;
          if (parse_tcp_timeout(ctx, key, is_idle ? TCP_IDLE_MIN_UNITS : TCP_INITIAL_MIN_UNITS, TCP_IDLE_MAX_UNITS, true,
                                is_idle ? &config->tcp_idle_timeout : &config->tcp_initial_timeout) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "version") == 0 || strcmp(key, "hostname") == 0 || strcmp(key, "server-id") == 0) {
          if (parse_chaos_statement(ctx, config, key) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "tcp-advertised-timeout") == 0) {
          /* RFC 7828 §3.3.2: the idle timeout the edns-tcp-keepalive option tells the client (BIND: advertised, in units of 100 ms, no minimum) */
          uint32_t ms = 0;
          if (parse_tcp_timeout(ctx, key, 0, TCP_ADVERTISED_MAX_UNITS, false, &ms) != 0) {
            free(key);
            return -1;
          }
          config->tcp_advertised_set = true;
          config->tcp_advertised_units = (uint16_t)(ms / 100 > TCP_ADVERTISED_MAX_UNITS ? TCP_ADVERTISED_MAX_UNITS : ms / 100);
        } else if (strcmp(key, "tcp-keepalive-timeout") == 0) {
          /* BIND: the idle timeout of a connection whose client sent edns-tcp-keepalive.  KariDNS has one idle timeout for every connection */
          uint32_t ms = 0;
          if (parse_tcp_timeout(ctx, key, 1, TCP_ADVERTISED_MAX_UNITS, false, &ms) != 0) {
            free(key);
            return -1;
          }
          conf_warn_here(ctx, "options tcp-keepalive-timeout", "accepted, no effect in KariDNS: every connection uses tcp-idle-timeout");
        } else if (strcmp(key, "cookie-secret") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) { free(key); free_token(&tok); return -1; }
          uint8_t secret[16];
          bool hex_ok = (strlen(tok.value) == 32);
          for (int hi = 0; hex_ok && hi < 16; hi++) {
            int hv = hex_nibble_value(tok.value[hi * 2]);
            int lv = hex_nibble_value(tok.value[hi * 2 + 1]);
            if (hv < 0 || lv < 0) { hex_ok = false; break; }
            secret[hi] = (uint8_t)((hv << 4) | lv);
          }
          if (!hex_ok) {
            syslog(LOG_ERR, "[Config] Invalid cookie-secret (must be exactly 32 hex digits = 128-bit SipHash-2-4 key, RFC 9018)");
            fprintf(stderr, "[ERROR] Invalid cookie-secret (must be exactly 32 hex digits = 128-bit SipHash-2-4 key, RFC 9018)\n");
            OPENSSL_cleanse(tok.value, strlen(tok.value));
            free(key); free_token(&tok); return -1;
          }
          if (config->cookie_secret_count >= 4) {
            syslog(LOG_ERR, "[Config] Too many cookie-secret entries (max 4)");
            fprintf(stderr, "[ERROR] Too many cookie-secret entries (max 4)\n");
            OPENSSL_cleanse(secret, sizeof(secret));
            OPENSSL_cleanse(tok.value, strlen(tok.value));
            free(key); free_token(&tok); return -1;
          }
          memcpy(config->cookie_secrets[config->cookie_secret_count++], secret, sizeof(secret));
          OPENSSL_cleanse(secret, sizeof(secret));
          OPENSSL_cleanse(tok.value, strlen(tok.value));
          free_token(&tok);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_SEMICOLON) { free(key); free_token(&tok); return -1; }
          free_token(&tok);
        } else if (strcmp(key, "cookie-algorithm") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) { free(key); free_token(&tok); return -1; }
          if (strcasecmp(tok.value, "siphash24") != 0) {
            /* RFC 9018 §6: SipHash-2-4 is the mandatory algorithm; the BIND aes/sha1/sha256
             * variants are not interoperable and are deliberately not implemented. */
            syslog(LOG_ERR, "[Config] cookie-algorithm '%s' is not supported (only siphash24, RFC 9018)", tok.value);
            fprintf(stderr, "[ERROR] cookie-algorithm '%s' is not supported (only siphash24, RFC 9018)\n", tok.value);
            free(key); free_token(&tok); return -1;
          }
          free_token(&tok);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_SEMICOLON) { free(key); free_token(&tok); return -1; }
          free_token(&tok);
        } else if (strcmp(key, "nsid") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) { free(key); free_token(&tok); return -1; }
          if (config->nsid_string) free(config->nsid_string);
          config->nsid_string = tok.value;
          tok.value = NULL;
          free_token(&tok);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_SEMICOLON) { free(key); free_token(&tok); return -1; }
          free_token(&tok);
        } else if (strcmp(key, "minimal-responses") == 0) {
          if (parse_minimal_responses(ctx, "options", &config->minimal_responses) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "minimal-any") == 0) {
          if (parse_bool_statement(ctx, NULL, key, &config->minimal_any) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "additional-from-auth") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) {
            free(key);
            free_token(&tok);
            return -1;
          }
          if (!parse_additional_from_auth(tok.value, &config->additional_from_auth)) {
            report_bad_value(ctx, NULL, key, tok.value, "yes, no or in-domain");
            free(key);
            free_token(&tok);
            return -1;
          }
          free_token(&tok);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(key);
            return -1;
          }
          free_token(&tok);
        } else if (strcmp(key, "query-log-max-qps") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) {
            free(key);
            free_token(&tok);
            return -1;
          }
          char *endptr;
          unsigned long v = strtoul(tok.value, &endptr, 10);
          if (*endptr == '\0') {
            config->query_log_max_qps = (uint32_t)v;
          } else {
            syslog(LOG_ERR, "[Config] Invalid query-log-max-qps value '%s'", tok.value);
            fprintf(stderr, "[ERROR] Invalid query-log-max-qps value '%s'\n", tok.value);
            free(key);
            free_token(&tok);
            return -1;
          }
          free_token(&tok);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(key);
            return -1;
          }
          free_token(&tok);
        } else if (strcmp(key, "query-log-buffer-size") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) {
            free(key);
            free_token(&tok);
            return -1;
          }
          char *endptr;
          unsigned long v = strtoul(tok.value, &endptr, 10);
          if (*endptr == '\0' && v >= 1024 && v <= 1048576 && ((v & (v - 1)) == 0)) {
            config->query_log_buffer_size = (uint32_t)v;
          } else {
            syslog(LOG_ERR, "[Config] Invalid query-log-buffer-size value '%s' (must be a power of 2 between 1024 and 1048576)", tok.value);
            fprintf(stderr, "[ERROR] Invalid query-log-buffer-size value '%s' (must be a power of 2 between 1024 and 1048576)\n", tok.value);
            free(key);
            free_token(&tok);
            return -1;
          }
          free_token(&tok);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(key);
            return -1;
          }
          free_token(&tok);
        } else if (strcmp(key, "allow-program-zones") == 0) {
          if (parse_bool_statement(ctx, NULL, key, &config->allow_program_zones) != 0) {
            free(key);
            return -1;
          }
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
        } else if (strcmp(key, "wire-cache-max-records") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) {
            free(key);
            free_token(&tok);
            return -1;
          }
          char *endptr;
          unsigned long v = strtoul(tok.value, &endptr, 10);
          if (*endptr != '\0' || tok.value[0] == '-' || isspace((unsigned char)tok.value[0])) {
            syslog(LOG_ERR, "[Config] Invalid wire-cache-max-records value '%s' (must be a non-negative integer)", tok.value);
            fprintf(stderr, "[ERROR] Invalid wire-cache-max-records value '%s' (must be a non-negative integer)\n", tok.value);
            free(key); free_token(&tok); return -1;
          }
          config->wire_cache_max_records = (uint32_t)v;
          free_token(&tok);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(key);
            return -1;
          }
          free_token(&tok);
        } else if (strcmp(key, "alias-resolver") == 0) {
          if (parse_alias_resolvers(ctx, "options", &config->alias_resolvers, &config->alias_resolvers_count) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "ixfr-history") == 0) {
          if (parse_transport_param(ctx, NULL, key, false, 0, IXFR_HISTORY_MAX, &config->ixfr_history) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "max-zone-records") == 0) {
          /* I2: the limits of one inbound transfer of every secondary zone (a zone { } value replaces them) */
          if (db_take_uint(ctx, key, false, 2, KARIDNS_DB_MAX_ZONE_RECORDS_MAX, &config->max_zone_records) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "max-zone-bytes") == 0) {
          if (db_take_uint(ctx, key, true, KARIDNS_DB_MAX_ZONE_BYTES_MIN, KARIDNS_DB_MAX_ZONE_BYTES_MAX,
                           &config->max_zone_bytes) != 0) {
            free(key);
            return -1;
          }
        } else if ((strncmp(key, "notify-retr", 11) == 0 || strcmp(key, "notify-tcp-timeout") == 0) &&
                   (nr_rc = parse_notify_retry_option(ctx, NULL, key, &config->notify_retry)) != 0) {
          if (nr_rc < 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "tcp-mss") == 0) {
          if (parse_transport_param(ctx, NULL, key, false, KARIDNS_TCP_MSS_MIN, KARIDNS_TCP_MSS_MAX,
                                    &config->tcp_mss) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "tcp-window") == 0) {
          if (parse_transport_param(ctx, NULL, key, true, KARIDNS_TCP_BUF_MIN, KARIDNS_TCP_BUF_MAX,
                                    &config->tcp_window) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "udp-bufsize") == 0) {
          int v = 0;
          if (parse_transport_param(ctx, NULL, key, false, KARIDNS_UDP_BUFSIZE_MIN, KARIDNS_UDP_BUFSIZE_MAX,
                                    &v) != 0) {
            free(key);
            return -1;
          }
          if (alias_note(ctx, config, 0, key, v) != 0) {
            free(key);
            return -1;
          }
          config->udp_bufsize = (uint16_t)v;
        } else if (strcmp(key, "udp-recvbuf-size") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) {
            free(key);
            free_token(&tok);
            return -1;
          }
          int sz = parse_buffer_size_value(tok.value);
          if (sz > 0 && alias_note(ctx, config, 1, key, sz) != 0) {
            free(key);
            free_token(&tok);
            return -1;
          }
          if (sz > 0) config->udp_recvbuf_size = sz;
          free_token(&tok);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(key);
            return -1;
          }
          free_token(&tok);
        } else if (strcmp(key, "response-cache-size") == 0) {
          /* 0 = 使わない。それ以外は 4K/16M のような大きさ (上限 1024M)。書き損じは誤りにする */
          int sz = 0;
          if (parse_transport_param(ctx, NULL, key, true, 0, 1024LL * 1024 * 1024, &sz) != 0) {
            free(key);
            return -1;
          }
          config->response_cache_size = (size_t)sz;
        } else if (strcmp(key, "udp-sndbuf-size") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) {
            free(key);
            free_token(&tok);
            return -1;
          }
          int sz = parse_buffer_size_value(tok.value);
          if (sz > 0 && alias_note(ctx, config, 2, key, sz) != 0) {
            free(key);
            free_token(&tok);
            return -1;
          }
          if (sz > 0) config->udp_sndbuf_size = sz;
          free_token(&tok);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "dnstap") == 0) {
          if (parse_dnstap_block(ctx, config) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "database") == 0) {
          if (parse_database_block(ctx, config) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "udp-receive-buffer") == 0 || strcmp(key, "udp-send-buffer") == 0) {
          bool rcv = key[4] == 'r';
          int v = 0;
          if (parse_bind_bufsize(ctx, key, &v) != 0 || alias_note(ctx, config, rcv ? 1 : 2, key, v) != 0) {
            free(key);
            return -1;
          }
          if (v > 0) {
            if (rcv) config->udp_recvbuf_size = v;
            else config->udp_sndbuf_size = v;
          }
        } else if (strcmp(key, "tcp-receive-buffer") == 0 || strcmp(key, "tcp-send-buffer") == 0) {
          bool rcv = key[4] == 'r';
          int v = 0;
          if (parse_bind_bufsize(ctx, key, &v) != 0) {
            free(key);
            return -1;
          }
          if (rcv) { config->tcp_rcvbuf = v; config->tcp_rcvbuf_set = true; }
          else { config->tcp_sndbuf = v; config->tcp_sndbuf_set = true; }
        } else if (strcmp(key, "max-udp-size") == 0) {
          if (parse_udp_size_option(ctx, config, "options max-udp-size", key, &config->udp_bufsize) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "edns-udp-size") == 0) {
          /* BIND: the size advertised in the queries the server sends to other servers (a resolver's); an authoritative answer is limited by max-udp-size */
          uint16_t ignored = 0;
          if (parse_udp_size_option(ctx, NULL, "options edns-udp-size", key, &ignored) != 0) {
            free(key);
            return -1;
          }
          conf_warn_here(ctx, "options edns-udp-size", "accepted, no effect in KariDNS: it is the size of the queries a resolver sends; max-udp-size limits the responses");
        } else if (strcmp(key, "catalog-zones") == 0) {
          if (parse_catalog_zones(ctx, "options", &config->catz_names, &config->catz_count) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "dnstap-output") == 0) {
          if (parse_dnstap_output(ctx, config) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "dnstap-identity") == 0 || strcmp(key, "dnstap-version") == 0) {
          if (parse_dnstap_text(ctx, config, key) != 0) {
            free(key);
            return -1;
          }
        } else if (strncmp(key, "fstrm-set-", 10) == 0 && fstrm_option_name(key)) {
          /* the libfstrm writer settings of BIND: KariDNS has its own writer (dnstap { queue-size }) */
          if (parse_fstrm_option(ctx, key) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "require-server-cookie") == 0) {
          if (parse_bool_statement(ctx, NULL, key, &config->require_server_cookie) != 0) {
            free(key);
            return -1;
          }
        } else if (zv_option_name(key)) {
          /* batch 7: max-records, max-zone-ttl, serial-update-method, masterfile-format, check-*: the default of every view and zone */
          if (parse_zv_option(ctx, "options", key, &config->zv, false) != 0) {
            free(key);
            return -1;
          }
        } else if (xo_option_name(key)) {
          /* batch 4: the default of every view and zone (BIND 9.20) */
          char owhat[64];
          snprintf(owhat, sizeof(owhat), "options %s", key);
          if (parse_xfr_option(ctx, owhat, key, &config->xo, false, NULL) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "transfers-in") == 0 || strcmp(key, "transfers-out") == 0 || strcmp(key, "transfers-per-ns") == 0 ||
                   strcmp(key, "serial-query-rate") == 0 || strcmp(key, "notify-rate") == 0 ||
                   strcmp(key, "startup-notify-rate") == 0) {
          if (parse_options_xfr_limit(ctx, config, key) < 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "notify") == 0) {
          if (parse_notify_mode(ctx, "options notify", &config->notify_mode) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "also-notify") == 0) {
          /* BIND 9.20 ARM: a global list of servers that also get NOTIFY; a zone or view statement overrides it.  A later statement
           * replaces the earlier one. */
          notify_targets_free(config->also_notify, config->also_notify_count);
          config->also_notify = NULL;
          config->also_notify_count = 0;
          if (parse_notify_targets(ctx, "options also-notify", &config->also_notify, &config->also_notify_count, false) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "allow-query") == 0 || strcmp(key, "allow-query-on") == 0 || strcmp(key, "allow-transfer") == 0 ||
                   strcmp(key, "allow-update") == 0 || strcmp(key, "allow-notify") == 0) {
          /* BIND 9.20 ARM: the default of every zone (a view's or a zone's own statement overrides it) */
          char owhat[48];
          snprintf(owhat, sizeof(owhat), "options %s", key);
          aml_t **slot = strcmp(key, "allow-query") == 0 ? &config->acl.query
                         : strcmp(key, "allow-query-on") == 0 ? &config->acl.query_on
                         : strcmp(key, "allow-transfer") == 0 ? &config->acl.transfer
                         : strcmp(key, "allow-update") == 0 ? &config->acl.update : &config->acl.notify;
          if (parse_aml_slot(ctx, owhat, slot) != 0) {
            free(key);
            return -1;
          }
        } else if (strcmp(key, "control-channel") == 0) {
          /* D17-3: it used to be skipped like any unknown option, so the control socket silently did not exist.  It is a
           * top-level statement (like in the sample configuration); say so instead of ignoring it. */
          syslog(LOG_ERR, "[Config] control-channel is written inside options { }: it is a top-level statement, "
                          "write it outside options { }");
          fprintf(stderr, "[ERROR] control-channel is written inside options { }: it is a top-level statement, "
                          "write it outside options { }\n");
          if (ctx) ctx->error_occurred = true;
          free(key);
          return -1;
        } else if (unknown_block_statement(ctx, "options", k_bind_options_options, key) != 0) {
          free(key);
          return -1;
        }
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
      /* ゾーンのエントリなどは view 名を固定長 (KARIDNS_VIEW_NAME_MAX、NUL 込み) で持つ。それより長い名前は
       * 切り詰められ、その view のゾーンの設定を引けなくなる (転送、リロード、UPDATE、応答) ので受け付けない */
      if (strlen(tok.value) >= KARIDNS_VIEW_NAME_MAX) {
        syslog(LOG_ERR, "[Config] View name '%.40s...' is longer than %d characters; rejecting configuration",
               tok.value, KARIDNS_VIEW_NAME_MAX - 1);
        fprintf(stderr, "[ERROR] View name '%.40s...' is longer than %d characters\n", tok.value,
                KARIDNS_VIEW_NAME_MAX - 1);
        free_token(&tok);
        if (ctx) ctx->error_occurred = true;
        return -1;
      }
      view_config_t *view = safe_calloc_or_die(1, sizeof(view_config_t));
      if (!view) { free_token(&tok); if (ctx) ctx->error_occurred = true; return -1; }
      view->name = tok.value;
      tok.value = NULL;
      free_token(&tok);
      {
        char vw[KARIDNS_VIEW_NAME_MAX + 16];
        snprintf(vw, sizeof(vw), "view '%s'", view->name);
        if (read_block_open(ctx, vw) != 0) { free(view->name); free(view); return -1; }
      }
      zone_config_t *last_view_zone = NULL;
      while (1) {
        tok = get_next_token(ctx);
        if (tok.type == TOKEN_RBRACE) { free_token(&tok); break; }
        if (tok.type != TOKEN_STRING) { free_partial_view(view); free_token(&tok); return -1; }
        if (strcmp(tok.value, "match-clients") == 0) {
          free_token(&tok);
          char mwhat[KARIDNS_VIEW_NAME_MAX + 32];
          snprintf(mwhat, sizeof(mwhat), "view '%s' match-clients", view->name);
          if (parse_aml_slot(ctx, mwhat, &view->acl.match) != 0) {
            free_partial_view(view);
            return -1;
          }
          /* match-clients is evaluated on the client address alone: a `key` element would never match, which is a mistake to report */
          if (aml_tree_has_key(view->acl.match, 0)) {
            conf_error(ctx, mwhat, "'key' entries are not supported in match-clients (address match only)");
            free_partial_view(view);
            return -1;
          }
          bool mclients_inexact = false;
          if (aml_flatten(ctx, view->acl.match, false, ACL_KEY_REJECT, &view->match_clients, &view->match_clients_count,
                          NULL, NULL, &mclients_inexact, 0) != 0) {
            free_partial_view(view);
            return -1;
          }
          free(view->match_clients_parsed);
          view->match_clients_parsed = acl_list_parse(view->match_clients, view->match_clients_count);
        } else if (strcmp(tok.value, "notify") == 0) {
          free_token(&tok);
          char nwhat[KARIDNS_VIEW_NAME_MAX + 32];
          snprintf(nwhat, sizeof(nwhat), "view '%s' notify", view->name);
          if (parse_notify_mode(ctx, nwhat, &view->notify_mode) != 0) {
            free_partial_view(view);
            return -1;
          }
        } else if (strcmp(tok.value, "also-notify") == 0) {
          /* overrides options' also-notify for the zones of this view that have none of their own (BIND 9.20 ARM) */
          free_token(&tok);
          char vwhat[KARIDNS_VIEW_NAME_MAX + 32];
          snprintf(vwhat, sizeof(vwhat), "view '%s' also-notify", view->name);
          notify_targets_free(view->also_notify, view->also_notify_count);
          view->also_notify = NULL;
          view->also_notify_count = 0;
          view->also_notify_set = true;
          if (parse_notify_targets(ctx, vwhat, &view->also_notify, &view->also_notify_count, false) != 0) {
            free_partial_view(view);
            return -1;
          }
        } else if (strcmp(tok.value, "allow-query") == 0 || strcmp(tok.value, "allow-query-on") == 0 ||
                   strcmp(tok.value, "allow-transfer") == 0 || strcmp(tok.value, "allow-update") == 0 ||
                   strcmp(tok.value, "allow-notify") == 0) {
          /* overrides options' statement for the zones of this view that have none of their own (BIND 9.20 ARM) */
          char vawhat[KARIDNS_VIEW_NAME_MAX + 48];
          snprintf(vawhat, sizeof(vawhat), "view '%s' %s", view->name, tok.value);
          aml_t **slot = strcmp(tok.value, "allow-query") == 0 ? &view->acl.query
                         : strcmp(tok.value, "allow-query-on") == 0 ? &view->acl.query_on
                         : strcmp(tok.value, "allow-transfer") == 0 ? &view->acl.transfer
                         : strcmp(tok.value, "allow-update") == 0 ? &view->acl.update : &view->acl.notify;
          free_token(&tok);
          if (parse_aml_slot(ctx, vawhat, slot) != 0) {
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
          if (!z) continue; /* a zone type that is not loaded (zone_type_is_skipped) */
          /* 重複は検索と同じ規則で判定する ("example.test" と "example.test." は同じゾーン) */
          int ins = zone_cfg_index_insert(&view->zone_index, z, NULL);
          if (ins != 0) {
            if (ins > 0) {
              syslog(LOG_ERR, "[Config] Duplicate zone '%s' defined in view '%s'; rejecting configuration", z->domain, view->name);
              fprintf(stderr, "[ERROR] Duplicate zone '%s' defined in view '%s'\n", z->domain, view->name);
            } else {
              syslog(LOG_ERR, "[Config] Out of memory indexing zone '%s'", z->domain);
            }
            free_zone_config(z);
            free_partial_view(view);
            return -1;
          }
          if (!view->zones) view->zones = z; else last_view_zone->next = z;
          last_view_zone = z;
        } else if (strcmp(tok.value, "server") == 0) {
          /* batch 5: the view's own server statements replace the top-level ones as a whole (BIND named_config_get(cfgmaps, "server")) */
          free_token(&tok);
          char vscope[KARIDNS_VIEW_NAME_MAX + 16];
          snprintf(vscope, sizeof(vscope), "view '%s' ", view->name);
          if (parse_server_block(ctx, &view->servers, vscope) != 0) {
            free_partial_view(view);
            return -1;
          }
        } else if (strcmp(tok.value, "key") == 0) {
          /* batch 5: a key that only this view's statements, ACLs and server statements can use.  Its name must be new: BIND puts the global
           * keys and the view's into one ring and refuses a second key of the same name (bin/named/tsigconf.c, lib/isccfg/check.c) */
          free_token(&tok);
          tsig_key_t *vk = parse_key_block(ctx);
          if (!vk) {
            free_partial_view(view);
            return -1;
          }
          tsig_key_t **tail = &view->keys;
          bool dup = false;
          for (; *tail; tail = &(*tail)->next)
            if (domain_names_match_ci((*tail)->name, vk->name)) dup = true;
          if (dup) {
            syslog(LOG_ERR, "[Config] view '%s': duplicate TSIG key '%s' defined; rejecting configuration", view->name, vk->name);
            fprintf(stderr, "[ERROR] view '%s': duplicate TSIG key '%s' defined\n", view->name, vk->name);
            tsig_keys_free(vk);
            free_partial_view(view);
            if (ctx) ctx->error_occurred = true;
            return -1;
          }
          *tail = vk;
        } else if (strcmp(tok.value, "catalog-zones") == 0) {
          free_token(&tok);
          char cwhat[KARIDNS_VIEW_NAME_MAX + 16];
          snprintf(cwhat, sizeof(cwhat), "view '%s'", view->name);
          if (parse_catalog_zones(ctx, cwhat, &view->catz_names, &view->catz_count) != 0) { free_partial_view(view); return -1; }
        } else if (strcmp(tok.value, "max-udp-size") == 0 || strcmp(tok.value, "require-server-cookie") == 0) {
          /* batch 7: replaces options' for the clients of this view */
          bool is_udp = tok.value[0] == 'm';
          free_token(&tok);
          char vwhat[KARIDNS_VIEW_NAME_MAX + 16];
          snprintf(vwhat, sizeof(vwhat), "view '%s'", view->name);
          int vrc;
          if (is_udp) {
            vrc = parse_udp_size_option(ctx, NULL, vwhat, "max-udp-size", &view->max_udp_size);
          } else {
            vrc = parse_bool_statement(ctx, NULL, "require-server-cookie", &view->require_cookie);
            view->require_cookie_set = vrc == 0;
          }
          if (vrc != 0) { free_partial_view(view); return -1; }
        } else if (zv_option_name(tok.value)) {
          /* batch 7: the same options as options { }, for the zones of this view that have none of their own */
          char *zkey = tok.value;
          tok.value = NULL;
          free_token(&tok);
          char zwhat[KARIDNS_VIEW_NAME_MAX + 64];
          snprintf(zwhat, sizeof(zwhat), "view '%s'", view->name);
          int zrc = parse_zv_option(ctx, zwhat, zkey, &view->zv, false);
          free(zkey);
          if (zrc != 0) { free_partial_view(view); return -1; }
        } else if (xo_option_name(tok.value)) {
          /* batch 4: the transfer / NOTIFY options of the view replace options' for the zones of this view that have none of their own */
          char *xkey = tok.value;
          tok.value = NULL;
          free_token(&tok);
          char xwhat[KARIDNS_VIEW_NAME_MAX + 64];
          snprintf(xwhat, sizeof(xwhat), "view '%s' %s", view->name, xkey);
          int xrc = parse_xfr_option(ctx, xwhat, xkey, &view->xo, false, NULL);
          free(xkey);
          if (xrc != 0) { free_partial_view(view); return -1; }
        } else if (strcmp(tok.value, "database-file") == 0 || strcmp(tok.value, "database-schema") == 0 ||
                   strcmp(tok.value, "database") == 0) {
          char *vkey = tok.value;
          tok.value = NULL;
          free_token(&tok);
          int vrc = parse_view_database_option(ctx, view, vkey);
          free(vkey);
          if (vrc != 0) { free_partial_view(view); return -1; }
        } else {
          char *ukey = tok.value;
          tok.value = NULL;
          free_token(&tok);
          int urc = unknown_statement(ctx, "view", view->name, ukey, true);
          free(ukey);
          if (urc != 0) { free_partial_view(view); return -1; }
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
      if (!zone) continue; /* a zone type that is not loaded (zone_type_is_skipped); it does not make the configuration a "top-level zone" one */
      int ins = zone_cfg_index_insert(&config->top_zone_index, zone, NULL);
      if (ins != 0) {
        if (ins > 0) {
          syslog(LOG_ERR, "[Config] Duplicate zone '%s' defined (top-level); rejecting configuration", zone->domain);
          fprintf(stderr, "[ERROR] Duplicate zone '%s' defined\n", zone->domain);
        } else {
          syslog(LOG_ERR, "[Config] Out of memory indexing zone '%s'", zone->domain);
        }
        free_zone_config(zone);
        return -1;
      }
      saw_top_level_zone = true;
      if (!config->zones)
        config->zones = zone;
      else
        last_zone->next = zone;
      last_zone = zone;
    } else if (strcmp(tok.value, "remote-servers") == 0 || strcmp(tok.value, "primaries") == 0 ||
               strcmp(tok.value, "masters") == 0) {
      /* BIND 9.20 ARM "remote-servers" (primaries / masters are the older spellings): a named list of servers that also-notify { }
       * can name.  Read here, expanded after the whole file is read (a list may be written after its first use). */
      char stmt[16];
      snprintf(stmt, sizeof(stmt), "%s", tok.value);
      free_token(&tok);
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_STRING || !tok.value) {
        char db[96];
        conf_error(ctx, stmt, "expected a list name but found %s", tok_desc(&tok, db, sizeof(db)));
        free_token(&tok);
        return -1;
      }
      remote_list_t *rl = safe_calloc_or_die(1, sizeof(remote_list_t));
      if (!rl) { free_token(&tok); if (ctx) ctx->error_occurred = true; return -1; }
      rl->name = tok.value;
      tok.value = NULL;
      free_token(&tok);
      char loc[300];
      ctx_location(ctx, loc, sizeof(loc));
      rl->where = strdup(loc);
      bool dup_list = false;
      for (const remote_list_t *e = config->remote_lists; e; e = e->next)
        if (strcasecmp(e->name, rl->name) == 0) dup_list = true;
      rl->next = config->remote_lists; /* linked first: freed by free_server_config_fields() on any error */
      config->remote_lists = rl;
      if (dup_list) {
        conf_error(ctx, stmt, "list '%.64s' is defined twice", rl->name);
        return -1;
      }
      char lwhat[96];
      snprintf(lwhat, sizeof(lwhat), "%s '%.64s'", stmt, rl->name);
      if (parse_notify_targets(ctx, lwhat, &rl->items, &rl->count, false) != 0) return -1;
    } else if (strcmp(tok.value, "server") == 0) {
      free_token(&tok);
      if (parse_server_block(ctx, &config->servers, "") != 0) return -1;
    } else if (strcmp(tok.value, "acl") == 0) {
      /* D-22: acl "name" { <address_match_element>; ... }; (BIND named.conf) */
      free_token(&tok);
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_STRING) { free_token(&tok); return -1; }
      acl_def_t *acl = safe_calloc_or_die(1, sizeof(acl_def_t));
      if (!acl) { free_token(&tok); if (ctx) ctx->error_occurred = true; return -1; }
      acl->name = tok.value;
      tok.value = NULL;
      free_token(&tok);
      /* 先にリストへつなぐ。途中のエラーでも free_server_config_fields() が解放する */
      bool dup_name = false;
      for (const acl_def_t *e = config->acls; e; e = e->next)
        if (strcasecmp(e->name, acl->name) == 0) dup_name = true;
      acl->next = config->acls;
      config->acls = acl;
      if (dup_name || acl_name_is_builtin(acl->name)) {
        syslog(LOG_ERR, "[Config] acl '%s' is %s", acl->name, dup_name ? "defined twice" : "a built-in name");
        fprintf(stderr, "[ERROR] acl '%s' is %s\n", acl->name, dup_name ? "defined twice" : "a built-in name");
        if (ctx) ctx->error_occurred = true;
        return -1;
      }
      {
        char awhat[DNS_NAME_TEXT_SIZE + 16];
        snprintf(awhat, sizeof(awhat), "acl '%.255s'", acl->name);
        acl->aml = parse_aml_statement(ctx, awhat);
        if (!acl->aml) return -1;
        bool inexact = false;
        if (aml_flatten(ctx, acl->aml, false, ACL_KEY_MARKED, &acl->entries, &acl->count, NULL, NULL, &inexact, 0) != 0) return -1;
      }
    } else if (strcmp(tok.value, "key") == 0) {
      free_token(&tok);
      tsig_key_t *tsig = parse_key_block(ctx);
      if (!tsig) return -1;
      for (tsig_key_t *existing = config->keys; existing; existing = existing->next) {
        if (domain_names_match_ci(existing->name, tsig->name)) {
          syslog(LOG_ERR, "[Config] Duplicate TSIG key '%s' defined; rejecting configuration", tsig->name);
          fprintf(stderr, "[ERROR] Duplicate TSIG key '%s' defined\n", tsig->name);
          tsig_keys_free(tsig);
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
        char *key_prop = tok.value;
        tok.value = NULL;
        free_token(&tok);
        if (strcmp(key_prop, "algorithm") == 0 ||
            strcmp(key_prop, "secret") == 0 ||
            strcmp(key_prop, "socket") == 0 ||
            strcmp(key_prop, "socket-path") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) {
            free(key_prop);
            free_token(&tok);
            return -1;
          }
          char *val = tok.value;
          tok.value = NULL;
          free_token(&tok);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(key_prop);
            free(val);
            free_token(&tok);
            return -1;
          }
          free_token(&tok);
          if (strcmp(key_prop, "socket") == 0 || strcmp(key_prop, "socket-path") == 0) {
            if (config->control.socket_path) free(config->control.socket_path);
            config->control.socket_path = val;
          } else if (strcmp(key_prop, "algorithm") == 0) {
            if (!tsig_algorithm_is_supported(val)) {
              syslog(LOG_ERR, "[Config] Unsupported TSIG algorithm in controls: %s", val);
              fprintf(stderr, "[ERROR] Unsupported TSIG algorithm in controls: %s\n", val);
              free(key_prop);
              free(val);
              return -1;
            }
            if (strstr(val, "md5") || strstr(val, "sha1")) {
              syslog(LOG_WARNING, "[Config] Warning: TSIG algorithm '%s' is deprecated and insecure (RFC 8945)", val);
            }
            if (config->control.algorithm) free(config->control.algorithm);
            config->control.algorithm = val;
          } else {
            if (config->control.secret) free(config->control.secret);
            config->control.secret = val;
            size_t slen = strlen(config->control.secret);
            size_t decoded_upper_bound = ((slen + 3) / 4) * 3;
            if (slen == 0 || decoded_upper_bound > sizeof(config->control.secret_decoded)) {
              syslog(LOG_ERR, "[Config] secret too long for algorithm (decodes to %zu bytes, max %zu)", decoded_upper_bound, sizeof(config->control.secret_decoded));
              fprintf(stderr, "[ERROR] secret too long for algorithm\n");
              free(key_prop);
              free(config->control.secret);
              config->control.secret = NULL;
              return -1;
            }
            int len = EVP_DecodeBlock(config->control.secret_decoded,
                                      (const unsigned char *)config->control.secret,
                                      slen);
            if (len < 0) {
              syslog(LOG_ERR, "[Config] control-channel: secret is not valid base64");
              fprintf(stderr, "[ERROR] control-channel: secret is not valid base64\n");
              free(key_prop);
              free(config->control.secret);
              config->control.secret = NULL;
              return -1;
            }
            int padding = 0;
            if (slen > 0 && config->control.secret[slen - 1] == '=')
              padding++;
            if (slen > 1 && config->control.secret[slen - 2] == '=')
              padding++;
            config->control.secret_decoded_len = len - padding;
            if (strcmp(config->control.secret, KARIDNS_SAMPLE_SECRET_PLACEHOLDER) == 0) {
              syslog(LOG_WARNING, "[Config] control-channel: secret is still the sample placeholder; "
                     "replace it with the output of 'openssl rand -base64 32'");
              fprintf(stderr, "[WARNING] control-channel: secret is still the sample placeholder; "
                      "replace it with the output of 'openssl rand -base64 32'\n");
            }
          }
        } else {
          /* An unknown key used to be skipped, so a misspelt "secret" or "socket" left the control channel without a secret
           * or on the default socket without a word.  It is a configuration error now (startup and reload alike; karicheck
           * conf shows it as an error because it runs this parser). */
          syslog(LOG_ERR, "[Config] control-channel: unknown option '%.64s' (supported: socket, secret, algorithm)", key_prop);
          fprintf(stderr, "[ERROR] control-channel: unknown option '%.64s' (supported: socket, secret, algorithm)\n", key_prop);
          if (ctx) ctx->error_occurred = true;
          free(key_prop);
          return -1;
        }
        free(key_prop);
      }
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_SEMICOLON) {
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
    } else if (strcmp(tok.value, "dnstap") == 0) {
      free_token(&tok);
      if (parse_dnstap_block(ctx, config) != 0) {
        return -1;
      }
    } else if (strcmp(tok.value, "logging") == 0) {
      free_token(&tok);
      if (parse_logging_statement(ctx, config) != 0) return -1;
    } else if (strcmp(tok.value, "controls") == 0) {
      free_token(&tok);
      if (parse_controls_statement(ctx, config) != 0) return -1;
    } else if (strcmp(tok.value, "statistics-channels") == 0) {
      /* BIND's HTTP statistics server (lib/isccfg/namedconf.c statschannel): not implemented; the block is skipped */
      char loc[300];
      ctx_location(ctx, loc, sizeof(loc));
      conf_warn_loc(loc, "statistics-channels", "KariDNS has no statistics channel; the statement is accepted and ignored");
      free_token(&tok);
      skip_unknown_block(ctx);
    } else {
      free_token(&tok);
      skip_unknown_block(ctx);
    }
  }
  if (config_apply_directory(ctx, config) != 0) return -1;
  if (chaos_finish(ctx, config) != 0) return -1;
  logging_finish(config);
  if (controls_resolve(ctx, config) != 0) return -1;
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
    if (!default_view) return -1;
    default_view->name = strdup("__default__");
    default_view->match_clients = safe_calloc_or_die(1, sizeof(char *));
    if (!default_view->name || !default_view->match_clients) {
      if (default_view->name) free(default_view->name);
      if (default_view->match_clients) free(default_view->match_clients);
      free(default_view);
      return -1;
    }
    default_view->match_clients[0] = strdup("any");
    if (!default_view->match_clients[0]) {
      free(default_view->name);
      free(default_view->match_clients);
      free(default_view);
      return -1;
    }
    default_view->match_clients_count = 1;
    default_view->match_clients_parsed = acl_list_parse(default_view->match_clients, default_view->match_clients_count);
    default_view->zones = config->zones;
    default_view->zone_index = config->top_zone_index;
    memset(&config->top_zone_index, 0, sizeof(config->top_zone_index));
    config->zones = NULL;
    config->views = default_view;
  }
  catz_apply(ctx, config);   /* batch 7: catalog-zones { zone "x"; } marks the zones it names (a zone with `catalog-zone yes;` already is one) */
  if (upd_policy_check(ctx, config) != 0) return -1;

  if (validate_database_config(ctx, config) != 0) return -1;

  // Inherit options.user as default program-user if unspecified
  for (view_config_t *v = config->views; v; v = v->next) {
    for (zone_config_t *z = v->zones; z; z = z->next) {
      if (z->type && strcasecmp(z->type, "program") == 0) {
        if (!zext(z)->program_user && config->user) {
          zone_ext_t *zx = zone_ext_mut(z);
          if (!zx) return -1;
          zx->program_user = strdup(config->user);
          if (!zx->program_user) return -1;
        }
      }
    }
  }

  /* BIND address match lists: names, keys and flags (before the flat lists below: its messages carry file:line) */
  if (resolve_all_acl_lists(ctx, config) != 0) return -1;
  /* listen-on, listen-on-v6, bind-address: the addresses to listen on (interface snapshot of start-up); blackhole's list */
  if (listen_lists_resolve(ctx, config) != 0) return -1;
  if (config_build_listen(ctx, config) != 0) return -1;

  /* D-22: 名前付き ACL の参照を展開し、アドレスでも ACL 名でもない要素を設定エラーにする。
   */
  {
    char where[DNS_NAME_TEXT_SIZE + 128];
    if (config->ecs_trusted_resolvers_count > 0 &&
        acl_expand_field(ctx, config, "options ecs-trusted-resolvers", ACL_USE_ADDRESS,
                         &config->ecs_trusted_resolvers, &config->ecs_trusted_resolvers_count,
                         &config->ecs_trusted_resolvers_parsed, NULL, NULL) != 0)
      return -1;
    /* database acl-ceiling: like allow-transfer (addresses, named ACLs, key "name"); the keys must exist */
    if (config->database.enabled && config->database.acl_ceiling_count > 0 &&
        acl_expand_field(ctx, config, "options database acl-ceiling", ACL_USE_TRANSFER,
                         &config->database.acl_ceiling, &config->database.acl_ceiling_count,
                         &config->database.acl_ceiling_parsed, &config->database.acl_ceiling_keys,
                         &config->database.acl_ceiling_keys_count) != 0)
      return -1;
    for (int i = 0; i < config->database.acl_ceiling_keys_count; i++) {
      if (!key_name_is_defined(config->keys, config->database.acl_ceiling_keys[i])) {
        db_cfg_error(ctx, "database acl-ceiling: key '%.64s' is not defined in any key {} block",
                     config->database.acl_ceiling_keys[i]);
        return -1;
      }
    }
    for (view_config_t *v = config->views; v; v = v->next) {
      ctx->scope_keys = v->keys;
      snprintf(where, sizeof(where), "view '%s' match-clients", v->name);
      if (acl_expand_field(ctx, config, where, ACL_USE_ADDRESS, &v->match_clients, &v->match_clients_count,
                           &v->match_clients_parsed, NULL, NULL) != 0)
        return -1;
      for (zone_config_t *z = v->zones; z; z = z->next) {
        zone_ext_t *zx = z->ext; /* ext が無いゾーンは ACL を 1 つも持たない */
        if (!zx) continue;
        snprintf(where, sizeof(where), "zone '%s' allow-transfer", z->domain);
        if (acl_expand_field(ctx, config, where, ACL_USE_TRANSFER, &zx->allow_transfer, &zx->allow_transfer_count,
                             &zx->allow_transfer_parsed, &zx->tsig_keys, &zx->tsig_keys_count) != 0)
          return -1;
        snprintf(where, sizeof(where), "zone '%s' allow-update", z->domain);
        if (acl_expand_field(ctx, config, where, ACL_USE_UPDATE, &zx->allow_update, &zx->allow_update_count,
                             &zx->allow_update_parsed, NULL, NULL) != 0)
          return -1;
        snprintf(where, sizeof(where), "zone '%s' ecs-trusted-resolvers", z->domain);
        if (acl_expand_field(ctx, config, where, ACL_USE_ADDRESS, &zx->ecs_trusted_resolvers,
                             &zx->ecs_trusted_resolvers_count, &zx->ecs_trusted_resolvers_parsed, NULL, NULL) != 0)
          return -1;
      }
      ctx->scope_keys = NULL;
    }
  }

  /* also-notify: expand the remote-servers list names and check the TSIG keys */
  if (resolve_all_notify_targets(ctx, config) != 0) return -1;
  /* the source addresses the configuration names (start-up check, the Router's NOTIFY sockets, the connect broker) */
  if (config_collect_xfr_sources(ctx, config) != 0) return -1;

  /* [T7] TSIGキー参照の未定義検出 (checkconf相当の健全性チェック) */
  for (view_config_t *v = config->views; v; v = v->next) {
    ctx->scope_keys = v->keys;
    for (zone_config_t *z = v->zones; z; z = z->next) {
      const zone_ext_t *zx = z->ext;
      if (!zx) continue; /* tsig-key も allow-transfer key も持たない */
      /* tsig-key ディレクティブ: 存在しないキー名は起動失敗 */
      if (zx->tsig_key && !key_is_defined(ctx, config, zx->tsig_key)) {
        syslog(LOG_ERR, "[Config] Zone '%s': tsig-key '%s' is not defined in any key {} block",
               z->domain, zx->tsig_key);
        fprintf(stderr, "[ERROR] Zone '%s': tsig-key '%s' is not defined in any key {} block\n",
                z->domain, zx->tsig_key);
        return -1;
      }
      /* allow-transfer key: 存在しないキー名は起動失敗 */
      for (int i = 0; i < zx->tsig_keys_count; i++) {
        if (!key_is_defined(ctx, config, zx->tsig_keys[i])) {
          syslog(LOG_ERR, "[Config] Zone '%s': allow-transfer key '%s' is not defined in any key {} block",
                 z->domain, zx->tsig_keys[i]);
          fprintf(stderr, "[ERROR] Zone '%s': allow-transfer key '%s' is not defined in any key {} block\n",
                  z->domain, zx->tsig_keys[i]);
          return -1;
        }
      }
    }
  }
  ctx->scope_keys = NULL;
  if (servers_check_keys(ctx, config) != 0) return -1;

  config->any_zone_tcp_opts = false;
  for (view_config_t *v = config->views; v && !config->any_zone_tcp_opts; v = v->next) {
    for (zone_config_t *z = v->zones; z; z = z->next) {
      const zone_ext_t *zx = z->ext;
      if (zx && (zx->zone_tcp_mss > 0 || zx->zone_tcp_window > 0 || zx->zone_tcp_sndbuf > 0)) {
        config->any_zone_tcp_opts = true;
        break;
      }
    }
  }

  for (log_channel_t *c = config->logging.channels; c; c = c->next) {
    if (!c->max_qps_specified) {
      c->max_qps = config->query_log_max_qps;
    }
  }

  return 0;
}

/* ---- options { directory } ---- */

static bool g_dir_pinned = false;
static char *g_dir_pinned_val = NULL;

void config_pin_directory(const char *dir) {
  free(g_dir_pinned_val);
  g_dir_pinned_val = dir ? strdup(dir) : NULL;
  g_dir_pinned = dir == NULL || g_dir_pinned_val != NULL;
}

void config_unpin_directory(void) {
  free(g_dir_pinned_val);
  g_dir_pinned_val = NULL;
  g_dir_pinned = false;
}

/* The value of the last `directory "..."` statement of an `options { }` block in text (the main configuration file only: nothing
 * is included, no file is opened).  The relative `include` statements that come before the statement in the file need the value
 * when they are read, and BIND applies `directory` to all of them.  Returns a new string, or NULL when there is none. */
static char *config_scan_directory(const char *text) {
  config_file_frame_t fr;
  memset(&fr, 0, sizeof(fr));
  fr.src = (char *)text;
  fr.len = strlen(text);
  char *found = NULL;
  int depth = 0;
  bool in_options = false;     /* depth 1 of an options block */
  bool stmt_start = true;      /* the next token begins a statement (at depth 0, or at depth 1 of options) */
  bool cand_options = false;   /* the token just read was the unquoted word `options` at the start of a top-level statement */
  char *key = NULL, *val = NULL;
  int nstr = 0;                /* string tokens of the statement being read at depth 1 of options */
  for (;;) {
    conf_token_t t = get_raw_token_from_frame(&fr);
    if (t.type == TOKEN_EOF) { free_token(&t); break; }
    if (t.type == TOKEN_STRING && !t.value) break;
    if (t.type == TOKEN_LBRACE) {
      if (depth == 0 && cand_options) in_options = true;
      depth++;
      nstr = 0;
      cand_options = false;
      stmt_start = in_options && depth == 1;
    } else if (t.type == TOKEN_RBRACE) {
      if (depth > 0) depth--;
      if (depth == 0) in_options = false;
      nstr = 0;
      cand_options = false;
      stmt_start = depth == 0 || (in_options && depth == 1);
    } else if (t.type == TOKEN_SEMICOLON) {
      if (in_options && depth == 1 && nstr == 2 && key && val && strcmp(key, "directory") == 0) {
        free(found);
        found = strdup(val);
      }
      nstr = 0;
      cand_options = false;
      stmt_start = depth == 0 || (in_options && depth == 1);
    } else {
      cand_options = depth == 0 && stmt_start && !t.is_quoted && t.value && strcmp(t.value, "options") == 0;
      if (in_options && depth == 1) {
        if (nstr == 0) { free(key); key = t.value ? strdup(t.value) : NULL; }
        else if (nstr == 1) { free(val); val = t.value ? strdup(t.value) : NULL; }
        nstr++;
      }
      stmt_start = false;
    }
    free_token(&t);
  }
  free(key);
  free(val);
  return found;
}

int parse_named_conf_ext(const char *config_str, const char *initial_file_path, server_config_t *config) {
  if (!config_str || !config) return -1;
  token_ctx_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  if (initial_file_path) {
    ctx.stack[0].file_path = strdup(initial_file_path);
    if (!ctx.stack[0].file_path) {
      free_server_config_fields(config);
      return -1;
    }
  }
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

  /* the directory the relative `include` statements are read from: the one the server was started with, else the one the main file
   * writes (see config_scan_directory) */
  char *scanned = g_dir_pinned ? NULL : config_scan_directory(config_str);
  ctx.directory = g_dir_pinned ? g_dir_pinned_val : scanned;
  ctx.dir_pinned = g_dir_pinned;

  int res = parse_named_conf_internal(&ctx, config);

  free(ctx.dir_written);
  free(scanned);
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

/* ---- B8t-2: the settings of a zone travel from its primary to the secondaries (Extended AXFR v3, TYPE 65408) ---- */

typedef struct {
  char *buf;
  size_t cap, len;
  bool ovf;
} rs_t;

static void rs_add(rs_t *r, const char *s) {
  size_t n = strlen(s);
  if (r->ovf || r->len + n + 1 > r->cap) {
    r->ovf = true;
    return;
  }
  memcpy(r->buf + r->len, s, n);
  r->len += n;
  r->buf[r->len] = '\0';
}

static bool settings_key_name_ok(const char *k) {
  size_t n = k ? strlen(k) : 0;
  if (n == 0 || n > 255) return false;
  for (const char *p = k; *p; p++)
    if (!isalnum((unsigned char)*p) && *p != '.' && *p != '_' && *p != '-') return false;
  return true;
}

/* Is every address of the prefix inside options { database { acl-ceiling } }?  The first and the last address decide (and the
 * ends of the whole address space for "any"): a prefix the ceiling only partly covers is not sent. */
static bool cidr_inside_ceiling(const server_config_t *cfg, const cidr_entry_t *e) {
  char ip[INET6_ADDRSTRLEN];
  for (int fam = 0; fam < 2; fam++) {
    int af = fam == 0 ? AF_INET : AF_INET6;
    if (!e->is_any && e->family != af) continue;
    size_t n = fam == 0 ? 4 : 16;
    uint8_t lo[16] = {0}, hi[16] = {0};
    for (size_t i = 0; i < n; i++) {
      uint8_t a = e->is_any ? 0 : e->addr[i], m = e->is_any ? 0 : e->mask[i];
      lo[i] = a & m;
      hi[i] = (uint8_t)(a | (uint8_t)~m);
    }
    if (!inet_ntop(af, lo, ip, sizeof(ip)) || !db_ceiling_allows_address(cfg, ip)) return false;
    if (!inet_ntop(af, hi, ip, sizeof(ip)) || !db_ceiling_allows_address(cfg, ip)) return false;
  }
  return true;
}

static bool ceiling_has_key(const server_config_t *cfg, const char *name) {
  const database_config_t *d = &cfg->database;
  for (int i = 0; i < d->acl_ceiling_keys_count; i++)
    if (d->acl_ceiling_keys[i] && domain_names_match_ci(d->acl_ceiling_keys[i], name)) return true;
  return false;
}

/* "stmt { entries; key "k"; };": the ACL as the primary applies it.  For the ACL of a database zone (ceiling) only what lies inside
 * the ceiling is written; an entry this module cannot write (not an address, a key name with odd octets) makes the whole ACL
 * "none": the secondary must never get a wider list than the primary has. */
static void rs_acl(rs_t *r, const char *stmt, char *const *list, int n, char *const *keys, int nkeys, const char *zone_key,
                   bool ceiling, const server_config_t *cfg) {
  bool bad = false;
  for (int i = 0; i < n; i++) {
    const char *e = list[i] ? list[i] : "";
    if (!acl_entry_is_address(e[0] == '!' ? e + 1 : e)) bad = true;
  }
  for (int i = 0; i < nkeys; i++)
    if (!settings_key_name_ok(keys[i])) bad = true;
  if (zone_key && !settings_key_name_ok(zone_key)) bad = true;
  rs_add(r, stmt);
  rs_add(r, " {");
  int written = 0;
  for (int i = 0; !bad && i < n; i++) {
    const char *e = list[i];
    bool neg = e[0] == '!';
    const char *t = neg ? e + 1 : e;
    if (ceiling && !neg && strcmp(t, "none") != 0) {
      cidr_entry_t c;
      if (strcmp(t, "any") == 0) {
        memset(&c, 0, sizeof(c));
        c.is_any = true;
      } else if (!cidr_entry_parse(&c, t)) {
        continue;
      }
      if (!cidr_inside_ceiling(cfg, &c)) continue;
    }
    rs_add(r, " ");
    rs_add(r, e);
    rs_add(r, ";");
    if (!neg) written++;
  }
  for (int i = 0; !bad && i <= nkeys; i++) {
    const char *k = i < nkeys ? keys[i] : zone_key;
    if (!k) continue;
    if (ceiling && !ceiling_has_key(cfg, k)) continue;
    rs_add(r, " key \"");
    rs_add(r, k);
    rs_add(r, "\";");
    written++;
  }
  if (bad || written == 0) rs_add(r, " none;");
  rs_add(r, " };\n");
}

size_t zone_settings_render(const server_config_t *cfg, const zone_config_t *zcfg, bool omit_trusted, char *out, size_t cap) {
  if (!cfg || !out || cap < 16) return 0;
  out[0] = '\0';
  const zone_ext_t *x = zext(zcfg);
  rs_t r = { out, cap, 0, false };
  /* a database zone's ACLs also have to pass the ceiling (dns_tsig_acl.c); without a ceiling they refuse everybody */
  bool ceil = x->db_acl_ceiling;
  bool no_ceiling = ceil && !db_acl_ceiling_configured(cfg);
  bool is_master = zcfg && zcfg->type && strcasecmp(zcfg->type, "master") == 0;

  /* allow-transfer: the addresses, the keys, and (file zone of type master) the zone's tsig-key, which also may transfer */
  const char *zone_key = (is_master && !ceil && x->tsig_key) ? x->tsig_key : NULL;
  if (x->allow_transfer_count > 0 || x->tsig_keys_count > 0 || zone_key) {
    if (no_ceiling || (x->acl.transfer && x->acl.transfer->has_neg_key)) {   /* a negated key cannot be written in the flat form: nobody */
      rs_add(&r, "allow-transfer { none; };\n");
    } else {
      rs_acl(&r, "allow-transfer", x->allow_transfer, x->allow_transfer_count, x->tsig_keys, x->tsig_keys_count, zone_key, ceil, cfg);
    }
    if (x->transfer_acl_match == ACL_MATCH_ANY) rs_add(&r, "transfer-acl-match any;\n");
    else if (x->transfer_acl_match == ACL_MATCH_ALL) rs_add(&r, "transfer-acl-match all;\n");
  }

  /* ecs-trusted-resolvers: the list the zone has, else options' (the zone's data may carry its own list: omit_trusted) */
  if (!omit_trusted) {
    char *const *tl = x->ecs_trusted_resolvers_count > 0 ? x->ecs_trusted_resolvers : cfg->ecs_trusted_resolvers;
    int tn = x->ecs_trusted_resolvers_count > 0 ? x->ecs_trusted_resolvers_count : cfg->ecs_trusted_resolvers_count;
    if (tn > 0 && tl) {
      if (no_ceiling) rs_add(&r, "ecs-trusted-resolvers { none; };\n");
      else rs_acl(&r, "ecs-trusted-resolvers", tl, tn, NULL, 0, NULL, ceil && x->ecs_trusted_resolvers_count > 0, cfg);
    }
  }

  additional_from_auth_t afa = x->additional_from_auth_specified ? x->additional_from_auth : cfg->additional_from_auth;
  if (x->additional_from_auth_specified || afa != ADDITIONAL_AUTH_YES)
    rs_add(&r, afa == ADDITIONAL_AUTH_NO ? "additional-from-auth no;\n"
               : afa == ADDITIONAL_AUTH_IN_DOMAIN ? "additional-from-auth in-domain;\n" : "additional-from-auth yes;\n");

  unsigned bs = x->zone_udp_bufsize > 0 ? x->zone_udp_bufsize : cfg->udp_bufsize;
  if (bs >= KARIDNS_UDP_BUFSIZE_MIN && bs <= KARIDNS_UDP_BUFSIZE_MAX) {
    char tmp[48];
    snprintf(tmp, sizeof(tmp), "zone-udp-bufsize %u;\n", bs);
    rs_add(&r, tmp);
  }
  if (r.ovf) {
    out[0] = '\0';
    return (size_t)-1;
  }
  return r.len;
}

/* ---- a deep copy of a zone's option block, and the zone configuration of a secondary with the settings it received ---- */

static char *zx_strdup(const char *s) { return s ? strdup(s) : NULL; }

static void *zx_memdup(const void *p, size_t n) {
  if (!p || n == 0) return NULL;
  void *q = malloc(n);
  if (q) memcpy(q, p, n);
  return q;
}

static bool zx_strs(char ***dst, int *dn, char *const *src, int sn) {
  *dst = NULL;
  *dn = 0;
  if (sn <= 0 || !src) return true;
  char **a = calloc((size_t)sn, sizeof(char *));
  if (!a) return false;
  *dst = a;
  *dn = sn;
  for (int i = 0; i < sn; i++) {
    a[i] = zx_strdup(src[i]);
    if (src[i] && !a[i]) return false;
  }
  return true;
}

static bool zx_ipports(ip_port_t **dst, int *dn, const ip_port_t *src, int sn) {
  *dst = NULL;
  *dn = 0;
  if (sn <= 0 || !src) return true;
  ip_port_t *a = calloc((size_t)sn, sizeof(ip_port_t));
  if (!a) return false;
  *dst = a;
  *dn = sn;
  for (int i = 0; i < sn; i++) {
    a[i].port = src[i].port;
    a[i].ip = zx_strdup(src[i].ip);
    if (src[i].ip && !a[i].ip) return false;
  }
  return true;
}

static bool zx_notify_targets(notify_target_t **dst, int *dn, const notify_target_t *src, int sn) {
  *dst = NULL;
  *dn = 0;
  if (sn <= 0 || !src) return true;
  notify_target_t *a = calloc((size_t)sn, sizeof(*a));
  if (!a) return false;
  *dst = a;
  *dn = sn;
  for (int i = 0; i < sn; i++) {
    a[i].port = src[i].port;
    a[i].ip = zx_strdup(src[i].ip);
    a[i].key = zx_strdup(src[i].key);
    a[i].list = zx_strdup(src[i].list);
    a[i].where = zx_strdup(src[i].where);
    memcpy(a[i].src_set, src[i].src_set, sizeof(a[i].src_set));
    memcpy(a[i].src, src[i].src, sizeof(a[i].src));
    a[i].src_loc = zx_strdup(src[i].src_loc);
    if ((src[i].ip && !a[i].ip) || (src[i].key && !a[i].key) || (src[i].list && !a[i].list) || (src[i].where && !a[i].where) ||
        (src[i].src_loc && !a[i].src_loc))
      return false;
  }
  return true;
}

static bool zx_tags(struct ecs_tag_def_s **dst, int *dn, const struct ecs_tag_def_s *src, int sn) {
  *dst = NULL;
  *dn = 0;
  if (sn <= 0 || !src) return true;
  struct ecs_tag_def_s *a = calloc((size_t)sn, sizeof(*a));
  if (!a) return false;
  *dst = a;
  *dn = sn;
  for (int i = 0; i < sn; i++) {
    a[i].tag = zx_strdup(src[i].tag);
    if (src[i].tag && !a[i].tag) return false;
    if (src[i].cidr_count > 0 && src[i].cidrs) {
      a[i].cidrs = calloc((size_t)src[i].cidr_count, sizeof(ecs_cidr_entry_t));
      if (!a[i].cidrs) return false;
      a[i].cidr_count = src[i].cidr_count;
      for (int j = 0; j < src[i].cidr_count; j++) {
        a[i].cidrs[j].parsed = src[i].cidrs[j].parsed;
        a[i].cidrs[j].cidr = zx_strdup(src[i].cidrs[j].cidr);
        if (src[i].cidrs[j].cidr && !a[i].cidrs[j].cidr) return false;
      }
    }
  }
  return true;
}

/* A deep copy: the copy owns everything it points to (free_zone_ext()).  NULL when out of memory. */
static zone_ext_t *zone_ext_clone(const zone_ext_t *s) {
  zone_ext_t *d = calloc(1, sizeof(*d));
  if (!d) return NULL;
  *d = *s;
  /* every pointer of the copy is rebuilt below; until then it must not alias the source */
  d->masters = NULL; d->masters_count = 0; d->masters_parsed = NULL; /* notify_mode is copied with *d = *s */
  d->tsig_key = NULL;
  d->tsig_keys = NULL; d->tsig_keys_count = 0;
  d->also_notify = NULL; d->also_notify_count = 0; /* also_notify_set is copied with *d = *s */
  d->notify_source = NULL;
  d->xo = NULL;
  d->allow_transfer = NULL; d->allow_transfer_count = 0; d->allow_transfer_parsed = NULL;
  d->allow_update = NULL; d->allow_update_count = 0; d->allow_update_parsed = NULL;
  acl_set_copy(&d->acl, &s->acl);   /* the lists are immutable: shared by reference */
  d->rrl.exempt_clients = NULL; d->rrl.exempt_clients_count = 0; d->rrl.exempt_clients_parsed = NULL;
  d->program_path = NULL; d->program_args = NULL; d->program_args_count = 0; d->program_user = NULL;
  d->forwarders = NULL; d->forwarders_count = 0;
  d->file_format = NULL;
  d->upd_policy = NULL;
  d->alias_resolvers = NULL; d->alias_resolvers_count = 0;
  d->ecs_tags = NULL; d->ecs_tag_count = 0;
  d->location_tags = NULL; d->location_tag_count = 0;
  d->ecs_trusted_resolvers = NULL; d->ecs_trusted_resolvers_count = 0; d->ecs_trusted_resolvers_parsed = NULL;
  bool ok = zx_notify_targets(&d->masters, &d->masters_count, s->masters, s->masters_count) &&
            zx_strs(&d->tsig_keys, &d->tsig_keys_count, s->tsig_keys, s->tsig_keys_count) &&
            zx_notify_targets(&d->also_notify, &d->also_notify_count, s->also_notify, s->also_notify_count) &&
            zx_strs(&d->allow_transfer, &d->allow_transfer_count, s->allow_transfer, s->allow_transfer_count) &&
            zx_strs(&d->allow_update, &d->allow_update_count, s->allow_update, s->allow_update_count) &&
            zx_ipports(&d->rrl.exempt_clients, &d->rrl.exempt_clients_count, s->rrl.exempt_clients, s->rrl.exempt_clients_count) &&
            zx_strs(&d->program_args, &d->program_args_count, s->program_args, s->program_args_count) &&
            zx_ipports(&d->forwarders, &d->forwarders_count, s->forwarders, s->forwarders_count) &&
            zx_ipports(&d->alias_resolvers, &d->alias_resolvers_count, s->alias_resolvers, s->alias_resolvers_count) &&
            zx_tags(&d->ecs_tags, &d->ecs_tag_count, s->ecs_tags, s->ecs_tag_count) &&
            zx_tags(&d->location_tags, &d->location_tag_count, s->location_tags, s->location_tag_count) &&
            zx_strs(&d->ecs_trusted_resolvers, &d->ecs_trusted_resolvers_count, s->ecs_trusted_resolvers, s->ecs_trusted_resolvers_count);
  if (ok && s->tsig_key && !(d->tsig_key = strdup(s->tsig_key))) ok = false;
  if (ok && s->notify_source && !(d->notify_source = strdup(s->notify_source))) ok = false;
  if (ok && s->xo) {
    d->xo = calloc(1, sizeof(*d->xo));
    if (!d->xo || !xo_copy(d->xo, s->xo)) {
      free(d->xo);
      d->xo = NULL;
      ok = false;
    }
  }
  if (ok && s->program_path && !(d->program_path = strdup(s->program_path))) ok = false;
  if (ok && s->program_user && !(d->program_user = strdup(s->program_user))) ok = false;
  if (ok && s->file_format && !(d->file_format = strdup(s->file_format))) ok = false;
  if (ok && s->upd_policy && !(d->upd_policy = zx_memdup(s->upd_policy, sizeof(*s->upd_policy)))) ok = false;
  /* the parsed forms are plain arrays of structs without pointers */
  if (ok && s->masters_parsed && s->masters_count > 0 &&
      !(d->masters_parsed = zx_memdup(s->masters_parsed, (size_t)s->masters_count * sizeof(cidr_entry_t))))
    ok = false;
  if (ok && s->allow_transfer_parsed && s->allow_transfer_count > 0 &&
      !(d->allow_transfer_parsed = zx_memdup(s->allow_transfer_parsed, (size_t)s->allow_transfer_count * sizeof(acl_entry_t))))
    ok = false;
  if (ok && s->allow_update_parsed && s->allow_update_count > 0 &&
      !(d->allow_update_parsed = zx_memdup(s->allow_update_parsed, (size_t)s->allow_update_count * sizeof(acl_entry_t))))
    ok = false;
  if (ok && s->rrl.exempt_clients_parsed && s->rrl.exempt_clients_count > 0 &&
      !(d->rrl.exempt_clients_parsed = zx_memdup(s->rrl.exempt_clients_parsed, (size_t)s->rrl.exempt_clients_count * sizeof(cidr_entry_t))))
    ok = false;
  if (ok && s->ecs_trusted_resolvers_parsed && s->ecs_trusted_resolvers_count > 0 &&
      !(d->ecs_trusted_resolvers_parsed = zx_memdup(s->ecs_trusted_resolvers_parsed, (size_t)s->ecs_trusted_resolvers_count * sizeof(acl_entry_t))))
    ok = false;
  if (!ok) {
    free_zone_ext(d);
    return NULL;
  }
  return d;
}

/* Move the received statement lists into d (replacing d's), as parsed lists of their own. */
static const tsig_key_t *view_own_keys_of(const server_config_t *cfg, const char *view_name) {
  if (!cfg || !view_name || !view_name[0]) return NULL;
  for (const view_config_t *v = cfg->views; v; v = v->next)
    if (strcasecmp(v->name, view_name) == 0) return v->keys;
  return NULL;
}

static bool zx_take_acl(zone_ext_t *d, const zone_ext_t *rx, char *note, size_t notelen, const server_config_t *cfg, const char *view_name) {
  for (int i = 0; i < d->allow_transfer_count; i++) free(d->allow_transfer[i]);
  free(d->allow_transfer);
  free(d->allow_transfer_parsed);
  for (int i = 0; i < d->tsig_keys_count; i++) free(d->tsig_keys[i]);
  free(d->tsig_keys);
  d->allow_transfer = NULL; d->allow_transfer_parsed = NULL; d->allow_transfer_count = 0;
  d->tsig_keys = NULL; d->tsig_keys_count = 0;
  /* a key the secondary does not have: the ACL fails closed (as for a database zone), whatever else it lists */
  const char *missing = NULL;
  for (int i = 0; i < rx->tsig_keys_count && !missing; i++)
    if (!cfg || (!key_name_is_defined(cfg->keys, rx->tsig_keys[i]) && !key_name_is_defined(view_own_keys_of(cfg, view_name), rx->tsig_keys[i]))) missing = rx->tsig_keys[i];
  if (missing) {
    char *none[1] = { "none" };
    if (!zx_strs(&d->allow_transfer, &d->allow_transfer_count, none, 1)) return false;
    d->allow_transfer_parsed = acl_list_parse(d->allow_transfer, d->allow_transfer_count);
    if (note && notelen) snprintf(note, notelen, "the received allow-transfer names the TSIG key '%.64s', which is not defined here: transfers are refused", missing);
    return true;
  }
  if (!zx_strs(&d->allow_transfer, &d->allow_transfer_count, rx->allow_transfer, rx->allow_transfer_count) ||
      !zx_strs(&d->tsig_keys, &d->tsig_keys_count, rx->tsig_keys, rx->tsig_keys_count))
    return false;
  if (d->allow_transfer_count > 0) d->allow_transfer_parsed = acl_list_parse(d->allow_transfer, d->allow_transfer_count);
  return true;
}

zone_config_t *zone_config_with_received(const char *domain, const zone_config_t *base, const zone_ext_t *rx,
                                         const server_config_t *cfg, char *note, size_t notelen) {
  return zone_config_with_received_in_view(domain, NULL, base, rx, cfg, note, notelen);
}

zone_config_t *zone_config_with_received_in_view(const char *domain, const char *view_name, const zone_config_t *base, const zone_ext_t *rx,
                                                 const server_config_t *cfg, char *note, size_t notelen) {
  if (note && notelen) note[0] = '\0';
  zone_config_t *c = calloc(1, sizeof(*c));
  if (!c) return NULL;
  c->domain = strdup(domain);
  c->type = strdup(base && base->type ? base->type : "slave");
  c->file = base && base->file ? strdup(base->file) : NULL;
  c->is_catalog = base ? base->is_catalog : false;
  zone_ext_t *x = zone_ext_clone(zext(base));
  if (!c->domain || !c->type || (base && base->file && !c->file) || !x) {
    if (x) free_zone_ext(x);
    free_zone_config(c);
    return NULL;
  }
  c->ext = x;
  const zone_ext_t *b = zext(base);
  /* precedence: a statement written in the secondary's own zone {} > the received one > options (the lookups fall back to options
   * where the zone has no value) */
  if (rx && b->allow_transfer_count == 0 && b->tsig_keys_count == 0 && !b->acl.transfer &&
      rx->allow_transfer_count + rx->tsig_keys_count > 0) {
    if (!zx_take_acl(x, rx, note, notelen, cfg, view_name)) {
      free_zone_config(c);
      return NULL;
    }
    if (b->transfer_acl_match == ACL_MATCH_DEFAULT) x->transfer_acl_match = rx->transfer_acl_match;
  }
  if (rx && b->ecs_trusted_resolvers_count == 0 && rx->ecs_trusted_resolvers_count > 0) {
    for (int i = 0; i < x->ecs_trusted_resolvers_count; i++) free(x->ecs_trusted_resolvers[i]);
    free(x->ecs_trusted_resolvers);
    free(x->ecs_trusted_resolvers_parsed);
    x->ecs_trusted_resolvers = NULL; x->ecs_trusted_resolvers_parsed = NULL; x->ecs_trusted_resolvers_count = 0;
    if (!zx_strs(&x->ecs_trusted_resolvers, &x->ecs_trusted_resolvers_count, rx->ecs_trusted_resolvers, rx->ecs_trusted_resolvers_count)) {
      free_zone_config(c);
      return NULL;
    }
    x->ecs_trusted_resolvers_parsed = acl_list_parse(x->ecs_trusted_resolvers, x->ecs_trusted_resolvers_count);
  }
  if (rx && !b->additional_from_auth_specified && rx->additional_from_auth_specified) {
    x->additional_from_auth = rx->additional_from_auth;
    x->additional_from_auth_specified = true;
  }
  if (rx && b->zone_udp_bufsize == 0 && rx->zone_udp_bufsize > 0) x->zone_udp_bufsize = rx->zone_udp_bufsize;
  return c;
}

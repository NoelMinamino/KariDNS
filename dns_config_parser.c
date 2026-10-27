#include "dns_config_parser.h"
#include <openssl/crypto.h>
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

/* everything x points to (not x itself: a zone_ext_shared_t embeds it) */
static void free_zone_ext_fields(zone_ext_t *x) {
  if (!x)
    return;
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

static void free_partial_view(view_config_t *view) {
  if (!view) return;
  zone_cfg_index_free(&view->zone_index);
  free_view_db_fields(view);
  if (view->name) free(view->name);
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
      if (!key_name_is_defined(cfg->keys, kname))
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
    if (use == ACL_USE_UPDATE && !neg && key_name_is_defined(cfg->keys, t)) {
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

void free_server_config_fields(server_config_t *cfg) {
  if (!cfg) return;
  for (int j = 0; j < cfg->bind_address_count; j++)
    free(cfg->bind_addresses[j]);
  free(cfg->bind_addresses);
  cfg->bind_addresses = NULL;
  cfg->bind_address_count = 0;

  if (cfg->user) { free(cfg->user); cfg->user = NULL; }
  if (cfg->group) { free(cfg->group); cfg->group = NULL; }
  if (cfg->pid_file) { free(cfg->pid_file); cfg->pid_file = NULL; }
  if (cfg->nsid_string) { free(cfg->nsid_string); cfg->nsid_string = NULL; }
  for (int j = 0; j < cfg->alias_resolvers_count; j++) free(cfg->alias_resolvers[j].ip);
  free(cfg->alias_resolvers);
  cfg->alias_resolvers = NULL;
  cfg->alias_resolvers_count = 0;
  notify_targets_free(cfg->also_notify, cfg->also_notify_count);
  cfg->also_notify = NULL;
  cfg->also_notify_count = 0;
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
    if (v->name) free(v->name);
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

  acl_def_t *a = cfg->acls;
  while (a) {
    acl_def_t *next_a = a->next;
    for (int i = 0; i < a->count; i++) free(a->entries[i]);
    free(a->entries);
    free(a->name);
    free(a);
    a = next_a;
  }
  cfg->acls = NULL;

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

/* The element grammar of also-notify and of the top-level remote-servers / primaries / masters lists, from the BIND 9.20 ARM
 * ("also-notify", "remote-servers"):
 *   [ port <integer> ] { ( <list-name> | <ipv4> [ port <integer> ] | <ipv6> [ port <integer> ] ) [ key <string> ]; ... };
 * `port` before the braces is the port of the elements that have none (default 53).  A name is not looked up here: the lists may be
 * written after the statement, so the names are expanded when the whole configuration has been read (expand_targets()).  `tls` and
 * `source` / `source-v6` are in the ARM grammar and are not supported: a clear error instead of a NOTIFY that goes somewhere else.
 * Appends to *list (the caller owns what was added also on failure); -1 with a message that names the place on a syntax error. */
static int parse_notify_targets(token_ctx_t *ctx, const char *what, notify_target_t **list, int *count, bool allow_cidr) {
  char db[96];
  int first = *count;
  int defport = 0;
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
      conf_error(ctx, what, "'%s' is not supported (the source address of NOTIFY is set with notify-source in zone { })", tok.value);
      free_token(&tok);
      return -1;
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
  for (int i = first; i < *count; i++)
    if ((*list)[i].ip && (*list)[i].port == 0) (*list)[i].port = defport ? defport : 53;
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
    if (zone_domain) {
      syslog(LOG_ERR, "[Config] zone '%s': invalid %s value '%s' (expected %lld..%lld%s)",
             zone_domain, name, s, lo, hi, suffix_hint);
      fprintf(stderr, "[ERROR] zone '%s': invalid %s value '%s' (expected %lld..%lld%s)\n",
              zone_domain, name, s, lo, hi, suffix_hint);
    } else {
      syslog(LOG_ERR, "[Config] Invalid %s value '%s' (expected %lld..%lld%s)", name, s, lo, hi, suffix_hint);
      fprintf(stderr, "[ERROR] Invalid %s value '%s' (expected %lld..%lld%s)\n", name, s, lo, hi, suffix_hint);
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

/* notify-retries / notify-retry-interval / notify-retry-backoff。options (zone_domain NULL) と zone で共通。
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
                             true, true, true};
  if (cfg) {
    r.retries = cfg->notify_retry.retries;
    r.interval = cfg->notify_retry.interval;
    r.backoff = cfg->notify_retry.backoff;
  }
  if (zone) {
    const zone_ext_t *x = zext(zone);
    if (x->notify_retry.retries_set) r.retries = x->notify_retry.retries;
    if (x->notify_retry.interval_set) r.interval = x->notify_retry.interval;
    if (x->notify_retry.backoff_set) r.backoff = x->notify_retry.backoff;
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
  "max-transfer-time-in", "max-transfer-time-out", "max-zone-ttl", "min-refresh-time", "min-retry-time", "multi-master",
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
  "min-cache-ttl", "min-ncache-ttl", "min-refresh-time", "min-retry-time", "minimal-any", "minimal-responses",
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

/* B7a: what a DB zone's settings text may contain (db_settings_parse).  The statements karidns-dbloader writes (the output
 * of build_settings() in dns_pdns_reader.c) and the profile texts of karidns_profiles are made of these. */
static const char *const k_db_zone_statements[] = {
  "allow-transfer", "allow-update", "also-notify", "tsig-key", "notify-retries", "notify-retry-interval",
  "notify-retry-backoff", "ixfr-history", "additional-from-auth", "disable-auto-tc-flag", "zone-udp-bufsize",
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
  conf_token_t tok = get_next_token(ctx);
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
    } else if (strcmp(key, "allow-transfer") == 0) {
      if (parse_acl_list(ctx, &x->allow_transfer, &x->allow_transfer_count, ACL_KEY_AS_TSIG_FIELD, &x->tsig_keys, &x->tsig_keys_count) != 0) {
        free(key); free_zone_config(zone); return -1;
      }
      free(x->allow_transfer_parsed);
      x->allow_transfer_parsed = acl_list_parse(x->allow_transfer, x->allow_transfer_count);
    } else if (strcmp(key, "allow-update") == 0) {
      if (parse_acl_list(ctx, &x->allow_update, &x->allow_update_count, ACL_KEY_AS_LIST_ENTRY, NULL, NULL) != 0) {
        free(key); free_zone_config(zone); return -1;
      }
      free(x->allow_update_parsed);
      x->allow_update_parsed = acl_list_parse(x->allow_update, x->allow_update_count);
    } else if (strcmp(key, "type") == 0 || strcmp(key, "file") == 0 ||
               strcmp(key, "file-format") == 0 ||
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
      else if (strcmp(key, "notify-source") == 0) {
        free(x->notify_source);
        x->notify_source = val;
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
    } else if (strncmp(key, "notify-retr", 11) == 0 &&
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

static int parse_dnstap_block(token_ctx_t *ctx, server_config_t *config) {
  conf_token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_LBRACE) { free_token(&tok); return -1; }
  free_token(&tok);
  config->dnstap.enabled = true;
  config->dnstap.queue_size = 4096;
  bool msg_type_specified = false;
  while (1) {
    tok = get_next_token(ctx);
    if (tok.type == TOKEN_RBRACE) { free_token(&tok); break; }
    if (tok.type != TOKEN_STRING) { free_token(&tok); return -1; }
    char *key_prop = tok.value;
    tok.value = NULL;
    free_token(&tok);
    tok = get_next_token(ctx);
    if (tok.type != TOKEN_STRING) { free(key_prop); free_token(&tok); return -1; }
    char *val = tok.value;
    tok.value = NULL;
    free_token(&tok);
    tok = get_next_token(ctx);
    if (tok.type != TOKEN_SEMICOLON) { free(key_prop); free(val); free_token(&tok); return -1; }
    free_token(&tok);

    if (strcmp(key_prop, "socket") == 0 || strcmp(key_prop, "socket-path") == 0) {
      if (config->dnstap.socket_path) free(config->dnstap.socket_path);
      config->dnstap.socket_path = val;
    } else if (strcmp(key_prop, "identity") == 0) {
      if (config->dnstap.identity) free(config->dnstap.identity);
      config->dnstap.identity = val;
    } else if (strcmp(key_prop, "version") == 0) {
      if (config->dnstap.version) free(config->dnstap.version);
      config->dnstap.version = val;
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
 * A `key` written on a list name is the key of those of its addresses that have none of their own.  Every key must be defined in a
 * key { } block (RFC 8945 needs the secret to sign).  -1 with a message on an unknown name, an undefined key, a list that includes
 * itself (nesting deeper than KARIDNS_REMOTE_LIST_DEPTH) or more than KARIDNS_ALSO_NOTIFY_MAX addresses. */
static int expand_targets(token_ctx_t *ctx, const server_config_t *cfg, const char *what, const notify_target_t *src, int n,
                          const char *inherit_key, int depth, notify_target_t **out, int *outn) {
  for (int i = 0; i < n; i++) {
    const notify_target_t *s = &src[i];
    const char *key = s->key ? s->key : inherit_key;
    if (s->key && !key_name_is_defined(cfg->keys, s->key)) {
      notify_cfg_error(ctx, s->where, what, "key '%.64s' is not defined in any key {} block", s->key);
      return -1;
    }
    if (s->list) {
      const remote_list_t *l = cfg->remote_lists;
      while (l && strcasecmp(l->name, s->list) != 0) l = l->next;
      if (!l) {
        notify_cfg_error(ctx, s->where, what, "'%.64s' is neither an IP address nor a remote-servers / primaries / masters list defined in this configuration",
                         s->list);
        return -1;
      }
      if (depth + 1 > KARIDNS_REMOTE_LIST_DEPTH) {
        notify_cfg_error(ctx, s->where, what, "remote-servers lists are nested more than %d deep (does list '%.64s' include itself?)",
                         KARIDNS_REMOTE_LIST_DEPTH, s->list);
        return -1;
      }
      if (expand_targets(ctx, cfg, what, l->items, l->count, key, depth + 1, out, outn) != 0) return -1;
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
    t->port = s->port;
    if (key) t->key = strdup(key);
    if (!t->ip || (key && !t->key)) {
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
  if (expand_targets(ctx, cfg, what, *list, *count, NULL, 0, &out, &outn) != 0) {
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
    int rc = expand_targets(ctx, config, what, l->items, l->count, NULL, 0, &tmp, &tn);
    notify_targets_free(tmp, tn);
    if (rc != 0) return -1;
  }
  if (resolve_notify_field(ctx, config, "options also-notify", &config->also_notify, &config->also_notify_count) != 0) return -1;
  for (view_config_t *v = config->views; v; v = v->next) {
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
  config->ixfr_history = IXFR_HISTORY_DEFAULT;
  config->max_zone_records = KARIDNS_DB_MAX_ZONE_RECORDS_DEFAULT;
  config->max_zone_bytes = KARIDNS_DB_MAX_ZONE_BYTES_DEFAULT;
  config->query_log_max_qps = 5000;
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
            strcmp(key, "group") == 0 || strcmp(key, "pid-file") == 0) {
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
            if (*endptr == '\0' && pval > 0 && pval <= 65535) config->port = (int)pval;
            free(val);
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
          tok = get_next_token(ctx);
          if (tok.type == TOKEN_LBRACE) {
            free_token(&tok);
            if (parse_string_list_inner(ctx, &config->bind_addresses,
                                  &config->bind_address_count) != 0) {
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
          /* ミリ秒 (0 = 既定の 10000)。tcp-initial-timeout は最初のメッセージまで、
           * tcp-idle-timeout はメッセージ間の待ち時間 (D-06、RFC 7766 §6.2.3) */
          uint32_t *dst = (strcmp(key, "tcp-idle-timeout") == 0) ? &config->tcp_idle_timeout
                                                                 : &config->tcp_initial_timeout;
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) { free(key); free_token(&tok); return -1; }
          char *endptr;
          errno = 0;
          unsigned long v = strtoul(tok.value, &endptr, 10);
          if (*endptr != '\0' || tok.value[0] == '-' || isspace((unsigned char)tok.value[0]) ||
              errno == ERANGE || v > UINT32_MAX) {
            syslog(LOG_ERR, "[Config] Invalid %s value '%s' (must be a non-negative integer of milliseconds)", key, tok.value);
            fprintf(stderr, "[ERROR] Invalid %s value '%s' (must be a non-negative integer of milliseconds)\n", key, tok.value);
            free(key); free_token(&tok); return -1;
          }
          *dst = (uint32_t)v;
          free_token(&tok);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_SEMICOLON) { free(key); free_token(&tok); return -1; }
          free_token(&tok);
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
          if (parse_bool_statement(ctx, NULL, key, &config->minimal_responses) != 0) {
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
        } else if (strncmp(key, "notify-retr", 11) == 0 &&
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
          config->udp_bufsize = (uint16_t)v;
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
                             ACL_KEY_REJECT, NULL, NULL) != 0) {
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
        } else if (strcmp(tok.value, "zone") == 0) {
          free_token(&tok);
          zone_config_t *z = NULL;
          if (parse_zone_block(ctx, &z) != 0) {
            free_partial_view(view);
            return -1;
          }
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
      if (parse_acl_list(ctx, &acl->entries, &acl->count, ACL_KEY_MARKED, NULL, NULL) != 0) return -1;
    } else if (strcmp(tok.value, "key") == 0) {
      free_token(&tok);
      tok = get_next_token(ctx);
      if (tok.type != TOKEN_STRING) {
        free_token(&tok);
        return -1;
      }
      tsig_key_t *tsig = safe_calloc_or_die(1, sizeof(tsig_key_t));
      if (!tsig) { free_token(&tok); if (ctx) ctx->error_occurred = true; return -1; }
      tsig->name = tok.value;
      tok.value = NULL;
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
        char *key_prop = tok.value;
        tok.value = NULL;
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
          char *val = tok.value;
          tok.value = NULL;
          free_token(&tok);
          if (!val) {
            free(key_prop);
            free(tsig->name);
            if (tsig->algorithm) free(tsig->algorithm);
            if (tsig->secret) free(tsig->secret);
            free(tsig);
            if (ctx) ctx->error_occurred = true;
            return -1;
          }
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
              syslog(LOG_ERR, "[Config] key '%s': secret is not valid base64", tsig->name);
              fprintf(stderr, "[ERROR] key '%s': secret is not valid base64\n", tsig->name);
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
            if (strcmp(tsig->secret, KARIDNS_SAMPLE_SECRET_PLACEHOLDER) == 0) {
              syslog(LOG_WARNING, "[Config] key '%s': secret is still the sample placeholder; "
                     "replace it with the output of 'openssl rand -base64 32'", tsig->name);
              fprintf(stderr, "[WARNING] key '%s': secret is still the sample placeholder; "
                      "replace it with the output of 'openssl rand -base64 32'\n", tsig->name);
            }
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
        if (domain_names_match_ci(existing->name, tsig->name)) {
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
        char *dir = tok.value;
        tok.value = NULL;
        free_token(&tok);
        if (strcmp(dir, "channel") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) {
            free(dir);
            free_token(&tok);
            return -1;
          }
          log_channel_t *ch = safe_calloc_or_die(1, sizeof(log_channel_t));
          if (!ch) {
            free(dir);
            free_token(&tok);
            if (ctx) ctx->error_occurred = true;
            return -1;
          }
          ch->name = tok.value;
          tok.value = NULL;
          free_token(&tok);
          ch->fd = -1;
          ch->max_qps = config->query_log_max_qps;
          ch->max_qps_specified = false;
          pthread_mutex_init(&ch->lock, NULL);
          /* 先にリストへつなぐ。途中のエラーでも free_server_config_fields() が解放する */
          ch->next = config->logging.channels;
          config->logging.channels = ch;
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
              free(dir);
              free_token(&tok);
              return -1;
            }
            char *opt = tok.value;
            tok.value = NULL;
            free_token(&tok);
            if (strcmp(opt, "file") == 0) {
              tok = get_next_token(ctx);
              if (tok.type != TOKEN_STRING) {
                free(opt);
                free(dir);
                free_token(&tok);
                return -1;
              }
              if (ch->file_path) free(ch->file_path);
              ch->file_path = tok.value;
              tok.value = NULL;
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
                      size_t check_len = len;
                      if (check_len > 1 && (tok.value[check_len - 1] == 'B' || tok.value[check_len - 1] == 'b')) {
                        check_len--;
                      }
                      char last = tok.value[check_len - 1];
                      char numeric_part[64];
                      size_t numeric_len = len;
                      if (last == 'M' || last == 'm') {
                        mult = 1024 * 1024;
                        numeric_len = check_len - 1;
                      } else if (last == 'K' || last == 'k') {
                        mult = 1024;
                        numeric_len = check_len - 1;
                      } else if (last == 'G' || last == 'g') {
                        mult = 1024 * 1024 * 1024;
                        numeric_len = check_len - 1;
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
              bool *dst = (strcmp(opt, "print-time") == 0) ? &ch->print_time
                        : (strcmp(opt, "print-category") == 0) ? &ch->print_category
                        : &ch->print_severity;
              if (parse_bool_statement(ctx, NULL, opt, dst) != 0) {
                free(opt);
                free(dir);
                return -1;
              }
            } else if (strcmp(opt, "max-qps") == 0) {
              tok = get_next_token(ctx);
              if (tok.type == TOKEN_STRING) {
                char *endptr;
                unsigned long v = strtoul(tok.value, &endptr, 10);
                if (*endptr == '\0') {
                  ch->max_qps = (uint32_t)v;
                  ch->max_qps_specified = true;
                } else {
                  syslog(LOG_ERR, "[Config] Invalid max-qps value '%s'", tok.value);
                  fprintf(stderr, "[ERROR] Invalid max-qps value '%s'\n", tok.value);
                }
              }
              free_token(&tok);
              tok = get_next_token(ctx);
              if (tok.type == TOKEN_SEMICOLON)
                free_token(&tok);
            } else
              skip_unknown_block(ctx);
            free(opt);
          }
          tok = get_next_token(ctx);
          if (tok.type == TOKEN_SEMICOLON)
            free_token(&tok);
        } else if (strcmp(dir, "category") == 0) {
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_STRING) {
            free(dir);
            free_token(&tok);
            return -1;
          }
          char *cat_name = tok.value;
          tok.value = NULL;
          free_token(&tok);
          /* D-01: category <name> { <channel>; ... }; 先頭のチャネルを使い、残りは警告して無視する */
          char **slot = NULL;
          if (strcmp(cat_name, "queries") == 0) {
            slot = &config->logging.queries_channel_name;
          } else if (strcmp(cat_name, "responses") == 0) {
            slot = &config->logging.responses_channel_name;
          } else {
            syslog(LOG_WARNING, "[Config] Unknown logging category '%s', ignoring", cat_name);
            fprintf(stderr, "[WARNING] Unknown logging category '%s', ignoring\n", cat_name);
          }
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_LBRACE) {
            free(cat_name);
            free(dir);
            free_token(&tok);
            return -1;
          }
          free_token(&tok);
          if (slot) {
            free(*slot); /* 空のリストはそのカテゴリを出力しない */
            *slot = NULL;
          }
          while (1) {
            tok = get_next_token(ctx);
            if (tok.type == TOKEN_RBRACE) {
              free_token(&tok);
              break;
            }
            if (tok.type != TOKEN_STRING) {
              free(cat_name);
              free(dir);
              free_token(&tok);
              return -1;
            }
            if (slot && !*slot) {
              *slot = tok.value;
              tok.value = NULL;
            } else if (slot) {
              syslog(LOG_WARNING, "[Config] logging category '%s': only the first channel ('%s') is used, ignoring '%s'",
                     cat_name, *slot, tok.value);
              fprintf(stderr, "[WARNING] logging category '%s': only the first channel ('%s') is used, ignoring '%s'\n",
                      cat_name, *slot, tok.value);
            }
            free_token(&tok);
            tok = get_next_token(ctx);
            if (tok.type != TOKEN_SEMICOLON) {
              free(cat_name);
              free(dir);
              free_token(&tok);
              return -1;
            }
            free_token(&tok);
          }
          free(cat_name);
          tok = get_next_token(ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(dir);
            free_token(&tok);
            return -1;
          }
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
          if (ch->name && strcmp(ch->name, config->logging.queries_channel_name) == 0) {
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
          if (ch->name && strcmp(ch->name, config->logging.responses_channel_name) == 0) {
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
    }
  }

  /* also-notify: expand the remote-servers list names and check the TSIG keys */
  if (resolve_all_notify_targets(ctx, config) != 0) return -1;

  /* [T7] TSIGキー参照の未定義検出 (checkconf相当の健全性チェック) */
  for (view_config_t *v = config->views; v; v = v->next) {
    for (zone_config_t *z = v->zones; z; z = z->next) {
      const zone_ext_t *zx = z->ext;
      if (!zx) continue; /* tsig-key も allow-transfer key も持たない */
      /* tsig-key ディレクティブ: 存在しないキー名は起動失敗 */
      if (zx->tsig_key && !key_name_is_defined(config->keys, zx->tsig_key)) {
        syslog(LOG_ERR, "[Config] Zone '%s': tsig-key '%s' is not defined in any key {} block",
               z->domain, zx->tsig_key);
        fprintf(stderr, "[ERROR] Zone '%s': tsig-key '%s' is not defined in any key {} block\n",
                z->domain, zx->tsig_key);
        return -1;
      }
      /* allow-transfer key: 存在しないキー名は起動失敗 */
      for (int i = 0; i < zx->tsig_keys_count; i++) {
        if (!key_name_is_defined(config->keys, zx->tsig_keys[i])) {
          syslog(LOG_ERR, "[Config] Zone '%s': allow-transfer key '%s' is not defined in any key {} block",
                 z->domain, zx->tsig_keys[i]);
          fprintf(stderr, "[ERROR] Zone '%s': allow-transfer key '%s' is not defined in any key {} block\n",
                  z->domain, zx->tsig_keys[i]);
          return -1;
        }
      }
    }
  }

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
    if (no_ceiling) {
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
    if ((src[i].ip && !a[i].ip) || (src[i].key && !a[i].key) || (src[i].list && !a[i].list) || (src[i].where && !a[i].where)) return false;
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
  d->allow_transfer = NULL; d->allow_transfer_count = 0; d->allow_transfer_parsed = NULL;
  d->allow_update = NULL; d->allow_update_count = 0; d->allow_update_parsed = NULL;
  d->rrl.exempt_clients = NULL; d->rrl.exempt_clients_count = 0; d->rrl.exempt_clients_parsed = NULL;
  d->program_path = NULL; d->program_args = NULL; d->program_args_count = 0; d->program_user = NULL;
  d->forwarders = NULL; d->forwarders_count = 0;
  d->file_format = NULL;
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
  if (ok && s->program_path && !(d->program_path = strdup(s->program_path))) ok = false;
  if (ok && s->program_user && !(d->program_user = strdup(s->program_user))) ok = false;
  if (ok && s->file_format && !(d->file_format = strdup(s->file_format))) ok = false;
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
static bool zx_take_acl(zone_ext_t *d, const zone_ext_t *rx, char *note, size_t notelen, const server_config_t *cfg) {
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
    if (!cfg || !key_name_is_defined(cfg->keys, rx->tsig_keys[i])) missing = rx->tsig_keys[i];
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
  if (rx && b->allow_transfer_count == 0 && b->tsig_keys_count == 0 && rx->allow_transfer_count + rx->tsig_keys_count > 0) {
    if (!zx_take_acl(x, rx, note, notelen, cfg)) {
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

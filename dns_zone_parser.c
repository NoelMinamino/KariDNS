#include "dns_zone_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "dns_utils.h"
#include <string.h>
#include <strings.h>
#include <ctype.h>

#define IS_SPACE(c) ((c) == ' ' || (c) == '\t')
#define IS_NEWLINE(c) ((c) == '\n' || (c) == '\r')
#define MAX_FIELDS 64


int hex_char_to_val(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

void *arena_alloc(zone_arena_t *arena, size_t size) {
  if (arena->current_pool_idx + size > arena->current_pool_cap ||
      arena->data_pool_count == 0) {
    if (arena->data_pool_count >= 128)
      return NULL;
    if (arena->data_pool_count == 0)
      arena->current_pool_cap = 64 * 1024;
    else {
      arena->current_pool_cap *= 2;
      if (arena->current_pool_cap > 64 * 1024 * 1024)
        arena->current_pool_cap = 64 * 1024 * 1024;
    }
    if (size > arena->current_pool_cap)
      arena->current_pool_cap = size + (1024 * 1024);
    arena->data_pools[arena->data_pool_count] = malloc(arena->current_pool_cap);
    if (!arena->data_pools[arena->data_pool_count])
      return NULL;
    arena->current_pool_idx = 0;
    arena->data_pool_count++;
  }
  void *ptr =
      &arena->data_pools[arena->data_pool_count - 1][arena->current_pool_idx];
  arena->current_pool_idx += size;
  return ptr;
}

static char *expand_domain_name(char *name, const char *origin,
                                zone_arena_t *arena) {
  if (!name)
    return name;
  size_t n_len = strlen(name);
  if (n_len > 0 && name[n_len - 1] == '.')
    return name;
  if (strcmp(name, "@") == 0) {
    if (!origin)
      return name;
    size_t o_len = strlen(origin);
    if (o_len > 0 && origin[o_len - 1] == '.')
      return (char *)origin;
    char *fqdn = (char *)arena_alloc(arena, o_len + 2);
    if (!fqdn)
      return (char *)origin;
    memcpy(fqdn, origin, o_len);
    fqdn[o_len] = '.';
    fqdn[o_len + 1] = '\0';
    return fqdn;
  }
  if (!origin) {
    char *fqdn = (char *)arena_alloc(arena, n_len + 2);
    if (!fqdn)
      return name;
    memcpy(fqdn, name, n_len);
    fqdn[n_len] = '.';
    fqdn[n_len + 1] = '\0';
    return fqdn;
  }
  size_t o_len = strlen(origin);
  bool origin_has_dot = (o_len > 0 && origin[o_len - 1] == '.');
  size_t total_len = n_len + 1 + o_len + (origin_has_dot ? 0 : 1);
  char *fqdn = (char *)arena_alloc(arena, total_len + 1);
  if (!fqdn)
    return name;
  memcpy(fqdn, name, n_len);
  fqdn[n_len] = '.';
  memcpy(fqdn + n_len + 1, origin, o_len);
  if (!origin_has_dot)
    fqdn[n_len + 1 + o_len] = '.';
  fqdn[total_len] = '\0';
  return fqdn;
}


#include <limits.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static char *resolve_include_path(const char *base_dir, const char *rel_path,
                                   bool is_standalone_mode, parse_error_t *err_out) {
    if (rel_path[0] == '\0') return NULL;

    // Reject absolute paths unless in standalone mode
    if (rel_path[0] == '/') {
        if (!is_standalone_mode) {
            if (err_out) err_out->error_message = "Absolute path in $INCLUDE is not allowed";
            return NULL;
        }
    }

    // Completely reject any directory traversal attempts (../)
    if (strstr(rel_path, "../") != NULL ||
        (strlen(rel_path) >= 2 && strcmp(rel_path + strlen(rel_path) - 2, "..") == 0)) {
        if (err_out) err_out->error_message = "Directory traversal (..) in $INCLUDE is not allowed";
        return NULL;
    }

    // Strip leading "./" to help with simple circular detection
    while (strncmp(rel_path, "./", 2) == 0) {
        rel_path += 2;
    }

    char raw[PATH_MAX];
    if (rel_path[0] == '/') {
        snprintf(raw, sizeof(raw), "%s", rel_path);
    } else {
        snprintf(raw, sizeof(raw), "%s/%s", base_dir, rel_path);
    }

    return strdup(raw);
}

#define MAX_INCLUDE_DEPTH 16

static int process_include(char **fields, int field_idx, zone_arena_t *arena,
                            parse_context_t *ctx, char **origin_io, char *cur_buf) {
    if (!ctx || !ctx->shared_ttl_io) {
        if (ctx && ctx->err_out) {
            ctx->err_out->error_message = "$INCLUDE requires shared_ttl_io to be configured by the caller";
        }
        return -1;
    }
    if (field_idx < 2) {
        if (ctx->err_out) ctx->err_out->error_message = "$INCLUDE requires a filename";
        return -1;
    }
    if (ctx->current_depth >= MAX_INCLUDE_DEPTH) {
        if (ctx->err_out) ctx->err_out->error_message = "$INCLUDE nesting too deep";
        return -1;
    }
    if (arena->file_buf_count >= 32) {
        if (ctx->err_out) ctx->err_out->error_message = "Too many $INCLUDE files (max 32)";
        return -1;
    }

    parse_error_t path_err = {0};
    char *resolved = resolve_include_path(ctx->base_dir, fields[1], ctx->is_standalone_mode, &path_err);
    if (!resolved) {
        if (ctx->err_out) {
            ctx->err_out->error_message = path_err.error_message;
            ctx->err_out->error_offset = (size_t)(fields[1] - cur_buf);
            ctx->err_out->token_length = strlen(fields[1]);
        }
        return -1;
    }

    // --- 循環検出: 祖先スタックの中に同じ解決済みパスがあれば拒否 ---
    for (int i = 0; i < ctx->visited_count; i++) {
        if (strcmp(ctx->visited_paths[i], resolved) == 0) {
            if (ctx->err_out) {
                ctx->err_out->error_message = "Circular $INCLUDE detected";
                ctx->err_out->error_offset = (size_t)(fields[1] - cur_buf);
                ctx->err_out->token_length = strlen(fields[1]);
                if (ctx->current_depth > 0) {
                    ctx->err_out->file_path = ctx->visited_paths[ctx->visited_count - 1];
                }
            }
            free(resolved);
            return -1;
        }
    }
    if (ctx->visited_count >= ctx->visited_cap) {
        if (ctx->err_out) ctx->err_out->error_message = "Ancestor path stack exhausted";
        free(resolved);
        return -1;
    }

    char *file_content = ctx->load_file_cb ? ctx->load_file_cb(ctx, resolved) : NULL;
    if (!file_content) {
        if (ctx->err_out) {
            ctx->err_out->error_message = "$INCLUDE file could not be read";
            ctx->err_out->error_offset = (size_t)(fields[1] - cur_buf);
            ctx->err_out->token_length = strlen(fields[1]);
            if (ctx->current_depth > 0) {
                ctx->err_out->file_path = ctx->visited_paths[ctx->visited_count - 1];
            }
        }
        free(resolved);
        return -1;
    }

    char *display_copy = strdup(file_content);
    if (!display_copy) {
        free(file_content);
        if (ctx->err_out) ctx->err_out->error_message = "Out of memory";
        free(resolved);
        return -1;
    }

    arena->file_bufs[arena->file_buf_count] = file_content;
    arena->display_bufs[arena->file_buf_count] = display_copy;
    arena->file_paths[arena->file_buf_count] = resolved;
    arena->file_buf_count++;

    char *saved_origin = *origin_io;
    char *child_origin = (field_idx > 2) ? fields[2] : *origin_io;

    ctx->visited_paths[ctx->visited_count++] = resolved;

    parse_context_t child_ctx = *ctx; 
    child_ctx.default_origin = child_origin;
    child_ctx.current_depth = ctx->current_depth + 1;
    child_ctx.shared_ttl_io = ctx->shared_ttl_io; 

    int rc = parse_zone_fast(file_content, strlen(file_content), arena, &child_ctx);

    if (rc < 0 && ctx && ctx->err_out && !ctx->err_out->file_path) {
        ctx->err_out->file_path = resolved;
    }

    ctx->visited_count--;

    *origin_io = saved_origin;

    return rc;
}

static dns_record_t *arena_alloc_record(zone_arena_t *arena, parse_context_t *ctx, const char *err_pos, const char *buf) {
    if (arena->count >= arena->records_cap) {
        size_t new_cap = arena->records_cap == 0 ? 16 : arena->records_cap * 2;
        dns_record_t *new_records = realloc(arena->records, new_cap * sizeof(dns_record_t));
        if (!new_records) {
            if (ctx && ctx->err_out) {
                ctx->err_out->error_message = "Out of memory";
                ctx->err_out->error_offset = (size_t)(err_pos - buf);
                ctx->err_out->token_length = 1;
            }
            return NULL;
        }
        memset(new_records + arena->records_cap, 0, (new_cap - arena->records_cap) * sizeof(dns_record_t));
        arena->records = new_records;
        arena->records_cap = new_cap;
    }
    return &arena->records[arena->count++];
}

#define MAX_GENERATE_COUNT 100000

typedef struct { uint64_t start, stop, step; } generate_range_t;

static int parse_generate_range(const char *range_str, generate_range_t *out, parse_error_t *err_out) {
    char *dash = strchr(range_str, '-');
    if (!dash) {
        if (err_out) err_out->error_message = "$GENERATE range must be start-stop[/step]";
        return -1;
    }
    char *endptr;
    uint64_t start = strtoull(range_str, &endptr, 10);
    if (endptr != dash) {
        if (err_out) err_out->error_message = "$GENERATE invalid start value";
        return -1;
    }
    uint64_t stop = strtoull(dash + 1, &endptr, 10);
    uint64_t step = 1;
    if (*endptr == '/') {
        step = strtoull(endptr + 1, &endptr, 10);
    }
    if (*endptr != '\0') {
        if (err_out) err_out->error_message = "$GENERATE invalid range syntax";
        return -1;
    }

    if (stop < start) {
        if (err_out) err_out->error_message = "$GENERATE range: stop must be >= start";
        return -1;
    }
    if (step == 0) {
        if (err_out) err_out->error_message = "$GENERATE step must not be 0";
        return -1;
    }
    if (start > 0xFFFFFFFFULL || stop > 0xFFFFFFFFULL) {
        if (err_out) err_out->error_message = "$GENERATE range: values must fit in 32-bit";
        return -1;
    }

    uint64_t count = (stop - start) / step + 1;
    if (count > MAX_GENERATE_COUNT) {
        if (err_out) err_out->error_message = "$GENERATE range exceeds maximum record count";
        return -1;
    }

    out->start = start; out->stop = stop; out->step = step;
    return 0;
}

static size_t expand_generate_template(const char *tmpl, uint64_t value, char *out, size_t out_cap, parse_error_t *err_out) {
    size_t out_len = 0;
    for (const char *p = tmpl; *p; ) {
        if (*p == '$') {
            p++;
            if (*p == '$') {
                if (out_len + 1 > out_cap) return (size_t)-1;
                out[out_len++] = '$';
                p++;
                continue;
            }
            long offset = 0;
            int width = 0;
            char base = 'd';
            if (*p == '{') {
                char *end;
                offset = strtol(p + 1, &end, 10);
                p = end;
                if (*p == ',') {
                    width = (int)strtol(p + 1, &end, 10);
                    p = end;
                    if (width < 0 || width > 64) {
                        if (err_out) err_out->error_message = "$GENERATE width out of range (0-64)";
                        return (size_t)-1;
                    }
                    if (*p == ',') {
                        base = *(p + 1);
                        p += 2;
                    }
                }
                if (*p != '}') {
                    if (err_out) err_out->error_message = "$GENERATE malformed ${...} substitution";
                    return (size_t)-1;
                }
                p++;
            }
            if (base != 'd' && base != 'o' && base != 'x' && base != 'X') {
                if (err_out) err_out->error_message = "$GENERATE base must be one of d,o,x,X";
                return (size_t)-1;
            }

            int64_t v = (int64_t)value + offset;
            char numbuf[32];
            const char *fmt = (base == 'd') ? "%0*lld" : (base == 'o') ? "%0*llo" : (base == 'x') ? "%0*llx" : "%0*llX";
            int n = snprintf(numbuf, sizeof(numbuf), fmt, width, (long long)v);
            if (n < 0 || (size_t)n >= sizeof(numbuf)) return (size_t)-1;
            if (out_len + (size_t)n > out_cap) return (size_t)-1;
            memcpy(out + out_len, numbuf, (size_t)n);
            out_len += (size_t)n;
        } else {
            if (out_len + 1 > out_cap) return (size_t)-1;
            out[out_len++] = *p++;
        }
    }
    if (out_len + 1 > out_cap) return (size_t)-1;
    out[out_len] = '\0';
    return out_len;
}

static int process_generate(char **fields, int field_idx, zone_arena_t *arena,
                             parse_context_t *ctx, const char *origin,
                             const char *default_ttl, const char *cur_buf) {
    if (field_idx < 5) {
        if (ctx->err_out) ctx->err_out->error_message = "$GENERATE requires range lhs type rhs";
        return -1;
    }
    parse_error_t local_err = {0};
    generate_range_t range;
    if (parse_generate_range(fields[1], &range, &local_err) != 0) {
        if (ctx->err_out) {
            ctx->err_out->error_message = local_err.error_message;
            ctx->err_out->error_offset = (size_t)(fields[1] - cur_buf);
            ctx->err_out->token_length = strlen(fields[1]);
        }
        return -1;
    }

    const char *lhs_tmpl = fields[2];
    const char *type_str = NULL;
    const char *rhs_tmpl = NULL;
    const char *class_str = "IN";
    const char *ttl_str = default_ttl;

    int i = 3;
    while (i < field_idx) {
        char first_char = fields[i][0];
        if (first_char >= '0' && first_char <= '9') {
            ttl_str = fields[i];
        } else if (strcasecmp(fields[i], "IN") == 0 || strcasecmp(fields[i], "CH") == 0) {
            class_str = fields[i];
        } else {
            type_str = fields[i];
            if (i + 1 < field_idx) {
                rhs_tmpl = fields[i + 1];
            }
            break;
        }
        i++;
    }

    if (!type_str || !rhs_tmpl) {
        if (ctx->err_out) {
            ctx->err_out->error_message = "$GENERATE requires range lhs [ttl] [class] type rhs";
            ctx->err_out->error_offset = (size_t)(fields[0] - cur_buf);
            ctx->err_out->token_length = strlen(fields[0]);
        }
        return -1;
    }

    uint16_t type_code = get_type_code(type_str);
    if (type_code != 1 && type_code != 28 && type_code != 2 &&
        type_code != 5 && type_code != 12 && type_code != 39 &&
        type_code != 16) {
        if (ctx->err_out) {
            ctx->err_out->error_message = "$GENERATE does not support this record type";
            ctx->err_out->error_offset = (size_t)(fields[3] - cur_buf);
            ctx->err_out->token_length = strlen(fields[3]);
        }
        return -1;
    }

    char name_buf[512], rdata_buf[512];
    for (uint64_t v = range.start; v <= range.stop; v += range.step) {
        size_t name_len = expand_generate_template(lhs_tmpl, v, name_buf, sizeof(name_buf), &local_err);
        if (name_len == (size_t)-1) {
            if (ctx->err_out) {
                ctx->err_out->error_message = local_err.error_message ? local_err.error_message : "$GENERATE lhs expansion failed";
                ctx->err_out->error_offset = (size_t)(fields[2] - cur_buf);
                ctx->err_out->token_length = strlen(fields[2]);
            }
            return -1;
        }
        size_t rdata_len = expand_generate_template(rhs_tmpl, v, rdata_buf, sizeof(rdata_buf), &local_err);
        if (rdata_len == (size_t)-1) {
            if (ctx->err_out) {
                ctx->err_out->error_message = local_err.error_message ? local_err.error_message : "$GENERATE rhs expansion failed";
                ctx->err_out->error_offset = (size_t)(fields[4] - cur_buf);
                ctx->err_out->token_length = strlen(fields[4]);
            }
            return -1;
        }

        dns_record_t *rec = arena_alloc_record(arena, ctx, fields[0], cur_buf);
        if (!rec) return -1;

        char *name_copy = arena_alloc(arena, name_len + 1);
        if (!name_copy) { if (ctx->err_out) ctx->err_out->error_message = "Out of memory"; return -1; }
        memcpy(name_copy, name_buf, name_len + 1);

        char *rdata_copy = arena_alloc(arena, rdata_len + 1);
        if (!rdata_copy) { if (ctx->err_out) ctx->err_out->error_message = "Out of memory"; return -1; }
        memcpy(rdata_copy, rdata_buf, rdata_len + 1);

        rec->name = expand_domain_name(name_copy, origin, arena);
        rec->ttl = (char *)ttl_str;
        rec->class_str = (char *)class_str;
        rec->type = (char *)type_str;
        rec->type_code = type_code;
        rec->rdata_count = 1;
        rec->rdata[0] = rdata_copy;

        if (type_code == 2 || type_code == 5 || type_code == 12 || type_code == 39) {
            rec->rdata[0] = expand_domain_name(rec->rdata[0], origin, arena);
        }

        if (v == UINT64_MAX) break;
    }
    return 0;
}

int parse_zone_fast(char *buf, size_t size, zone_arena_t *arena, parse_context_t *ctx) {
  char *prev_owner = NULL;
  char *origin = ctx ? (char *)ctx->default_origin : NULL;
  char *local_ttl_storage = NULL;
  char **prev_owner_io = &prev_owner;
  char **origin_io = &origin;
  char **default_ttl_str_io = (ctx && ctx->shared_ttl_io) ? ctx->shared_ttl_io : &local_ttl_storage;
  if (!buf || size == 0 || !arena)
    return -1;
  char *p = buf, *end = buf + size;
  int in_parens = 0, in_quotes = 0, field_idx = 0;
  char *fields[MAX_FIELDS], *token_start = NULL;

STATE_START_LINE:
  if (p >= end)
    goto DONE;
  field_idx = 0;
  in_quotes = 0;
  if (IS_SPACE(*p)) {
    if (*prev_owner_io)
      fields[field_idx++] = *prev_owner_io;
    goto SKIP_WHITESPACE;
  }
STATE_FIND_TOKEN:
  if (p >= end)
    goto PROCESS_RECORD;
  if (IS_SPACE(*p))
    goto SKIP_WHITESPACE;
  if (IS_NEWLINE(*p)) {
    *p++ = '\0';
    if (in_parens)
      goto STATE_FIND_TOKEN;
    goto PROCESS_RECORD;
  }
  if (*p == ';') {
    char *nl = memchr(p, '\n', end - p);
    if (!nl) {
      p = end;
      goto PROCESS_RECORD;
    }
    p = nl;
    goto STATE_FIND_TOKEN;
  }
  if (*p == '(') {
    in_parens = 1;
    *p++ = '\0';
    goto STATE_FIND_TOKEN;
  }
  if (*p == ')') {
    in_parens = 0;
    *p++ = '\0';
    goto STATE_FIND_TOKEN;
  }
  token_start = p;
  while (p < end) {
    if (*p == '\\') {
      p++;
      if (p < end)
        p++;
      continue;
    }
    if (*p == '"') {
      in_quotes = !in_quotes;
      p++;
      continue;
    }
    if (!in_quotes) {
      if (IS_SPACE(*p) || IS_NEWLINE(*p) || *p == ';' || *p == '(' || *p == ')')
        break;
    } else {
      if (IS_NEWLINE(*p))
        break;
    }
    p++;
  }
          if (field_idx < MAX_FIELDS)
            fields[field_idx++] = token_start;
          
          // ファイル末尾に到達した場合でも、最後のトークンのクォートを除去する
          if (p >= end) {
            if (field_idx > 0 && fields[field_idx - 1][0] == '"') {
              fields[field_idx - 1]++;
              size_t t_len = strlen(fields[field_idx - 1]);
              if (t_len > 0 && fields[field_idx - 1][t_len - 1] == '"')
                fields[field_idx - 1][t_len - 1] = '\0';
            }
            goto PROCESS_RECORD;
          }
  char delimiter = *p;
  *p++ = '\0';
  if (field_idx > 0 && fields[field_idx - 1][0] == '"') {
    fields[field_idx - 1]++;
    size_t t_len = strlen(fields[field_idx - 1]);
    if (t_len > 0 && fields[field_idx - 1][t_len - 1] == '"')
      fields[field_idx - 1][t_len - 1] = '\0';
  }
  if (IS_SPACE(delimiter))
    goto SKIP_WHITESPACE;
  if (IS_NEWLINE(delimiter)) {
    if (in_parens)
      goto STATE_FIND_TOKEN;
    goto PROCESS_RECORD;
  }
  if (delimiter == '(') {
    in_parens = 1;
    goto STATE_FIND_TOKEN;
  }
  if (delimiter == ')') {
    in_parens = 0;
    goto STATE_FIND_TOKEN;
  }
  if (delimiter == ';') {
    char *nl = memchr(p, '\n', end - p);
    if (!nl) {
      p = end;
      goto PROCESS_RECORD;
    }
    p = nl;
    goto STATE_FIND_TOKEN;
  }
SKIP_WHITESPACE:
  while (p < end && IS_SPACE(*p))
    p++;
  goto STATE_FIND_TOKEN;
PROCESS_RECORD:
  if (field_idx == 0) {
    if (p < end)
      goto STATE_START_LINE;
    goto DONE;
  }
  if (fields[0][0] == '$' && strcasecmp(fields[0], "$ORIGIN") == 0) {
    if (field_idx > 1)
      *origin_io = fields[1];
    if (p < end)
      goto STATE_START_LINE;
    goto DONE;
  }
    if (fields[0][0] == '$' && strcasecmp(fields[0], "$INCLUDE") == 0) {
        if (process_include(fields, field_idx, arena, ctx, origin_io, buf) < 0)
            return -1;
        if (p < end)
            goto STATE_START_LINE;
        goto DONE;
    }
    if (fields[0][0] == '$' && strcasecmp(fields[0], "$GENERATE") == 0) {
        if (process_generate(fields, field_idx, arena, ctx, *origin_io, *default_ttl_str_io, buf) != 0)
            return -1;
        if (p < end)
            goto STATE_START_LINE;
        goto DONE;
    }
  if (fields[0][0] == '$' && strcasecmp(fields[0], "$TTL") == 0) {
    if (field_idx > 1)
      *default_ttl_str_io = fields[1];
    if (p < end)
      goto STATE_START_LINE;
    goto DONE;
  }
    dns_record_t *rec = arena_alloc_record(arena, ctx, p, buf);
    if (!rec) return -1;
  rec->name = expand_domain_name(fields[0], *origin_io, arena);
  *prev_owner_io = rec->name;
  rec->ttl = *default_ttl_str_io;
  rec->class_str = NULL;
  rec->type = NULL;
  rec->rdata_count = 0;
  int i = 1;
  while (i < field_idx) {
    char first_char = fields[i][0];
    if (first_char >= '0' && first_char <= '9')
      rec->ttl = fields[i];
    else if ((first_char == 'I' && fields[i][1] == 'N' &&
              fields[i][2] == '\0') ||
             strcmp(fields[i], "CH") == 0)
      rec->class_str = fields[i];
    else {
      rec->type = fields[i];
      i++;
      break;
    }
    i++;
  }
  while (i < field_idx && rec->rdata_count < MAX_RDATA)
    rec->rdata[rec->rdata_count++] = fields[i++];
    
  if (!rec->type) {
    if (ctx && ctx->err_out) {
      ctx->err_out->error_message = "Missing record type";
      ctx->err_out->error_offset = field_idx > 0 ? (size_t)(fields[0] - buf) : (size_t)(p - buf);
      ctx->err_out->token_length = 1;
    }
    return -1;
  }
  
  rec->type_code = get_type_code(rec->type);
  if (rec->type_code == 0) {
    if (ctx && ctx->err_out) {
      ctx->err_out->error_message = "Unknown record type";
      ctx->err_out->error_offset = rec->type - buf;
      ctx->err_out->token_length = strlen(rec->type);
    }
    return -1;
  }
  rec->generic_len = 0;
  rec->generic_data = NULL;
  if (rec->rdata_count >= 2 && strcmp(rec->rdata[0], "\\#") == 0) {
    long declared_len = atol(rec->rdata[1]);
    if (declared_len < 0 || declared_len > 65535) {
      if (ctx && ctx->err_out) ctx->err_out->error_message = "Generic RDATA length (\\#) out of range (0-65535)";
      return -1;
    }
    rec->generic_len = (uint16_t)declared_len;
    if (rec->generic_len > 0 && rec->rdata_count > 2) {
      uint8_t *blob = (uint8_t *)arena_alloc(arena, rec->generic_len);
      if (blob) {
        size_t b_idx = 0;
        int high_nibble = -1;
        for (int j = 2; j < rec->rdata_count; j++) {
          for (char *h = rec->rdata[j]; *h; h++) {
            int val = hex_char_to_val(*h);
            if (val < 0)
              continue;
            if (high_nibble < 0)
              high_nibble = val;
            else {
              if (b_idx < rec->generic_len)
                blob[b_idx++] = (high_nibble << 4) | val;
              high_nibble = -1;
            }
          }
        }
        rec->generic_data = blob;
      }
    }
  } else if (rec->type) {
    if (rec->type_code == 5 || rec->type_code == 12 || rec->type_code == 2 ||
        rec->type_code == 39 || rec->type_code == 23 || 
        (rec->type_code >= 3 && rec->type_code <= 4) || 
        (rec->type_code >= 7 && rec->type_code <= 9)) {
      if (rec->rdata_count > 0)
        rec->rdata[0] = expand_domain_name(rec->rdata[0], *origin_io, arena);
    } else if (rec->type_code == 6) {
      if (rec->rdata_count > 0)
        rec->rdata[0] = expand_domain_name(rec->rdata[0], *origin_io, arena);
      if (rec->rdata_count > 1)
        rec->rdata[1] = expand_domain_name(rec->rdata[1], *origin_io, arena);
    } else if (rec->type_code == 15) {
      if (rec->rdata_count > 1)
        rec->rdata[1] = expand_domain_name(rec->rdata[1], *origin_io, arena);
    } else if (rec->type_code == 33) {
      if (rec->rdata_count > 3)
        rec->rdata[3] = expand_domain_name(rec->rdata[3], *origin_io, arena);
    } else if (rec->type_code == 35) { // NAPTR
      if (rec->rdata_count > 5)
        rec->rdata[5] = expand_domain_name(rec->rdata[5], *origin_io, arena);
    } else if (rec->type_code == 14 || rec->type_code == 17) {
      if (rec->rdata_count > 0)
        rec->rdata[0] = expand_domain_name(rec->rdata[0], *origin_io, arena);
      if (rec->rdata_count > 1)
        rec->rdata[1] = expand_domain_name(rec->rdata[1], *origin_io, arena);
    } else if (rec->type_code == 18 || rec->type_code == 36 || rec->type_code == 21 || rec->type_code == 107) {
      if (rec->rdata_count > 1)
        rec->rdata[1] = expand_domain_name(rec->rdata[1], *origin_io, arena);
    } else if (rec->type_code == 26) {
      if (rec->rdata_count > 1)
        rec->rdata[1] = expand_domain_name(rec->rdata[1], *origin_io, arena);
      if (rec->rdata_count > 2)
        rec->rdata[2] = expand_domain_name(rec->rdata[2], *origin_io, arena);
    } else if (rec->type_code == 45) { // IPSECKEY
      if (rec->rdata_count > 3 && atoi(rec->rdata[1]) == 3) {
        rec->rdata[3] = expand_domain_name(rec->rdata[3], *origin_io, arena);
      }
    } else if (rec->type_code == 260) { // AMTRELAY
      if (rec->rdata_count > 3 && atoi(rec->rdata[2]) == 3) {
        rec->rdata[3] = expand_domain_name(rec->rdata[3], *origin_io, arena);
      }
    } else if (rec->type_code == 55) { // HIP
      if (rec->rdata_count >= 4) {
        for (int i = 3; i < rec->rdata_count; i++) {
          rec->rdata[i] = expand_domain_name(rec->rdata[i], *origin_io, arena);
        }
      }
    } else if (rec->type_code == 64 || rec->type_code == 65) { // SVCB / HTTPS
      if (rec->rdata_count > 1) {
        if (strcmp(rec->rdata[1], ".") != 0) {
          rec->rdata[1] = expand_domain_name(rec->rdata[1], *origin_io, arena);
        }
      }
    } else if (rec->type_code == 22) { // NSAP
      if (rec->rdata_count > 0) {
        char *raw = rec->rdata[0];
        // "0x" または "0X" で始まっていればスキップ
        if (raw[0] == '0' && (raw[1] == 'x' || raw[1] == 'X')) {
            raw += 2;
        }
        size_t len = strlen(raw);
        char *clean = arena_alloc(arena, len + 1);
        if (clean) {
          size_t c_idx = 0;
          for (size_t k = 0; k < len; k++) {
            if (raw[k] != '.') { // ドットを除去
              clean[c_idx++] = raw[k];
            }
          }
          clean[c_idx] = '\0';
          rec->rdata[0] = clean; // 正規化された純粋なHex文字列に置き換え
        }
      }
    } else if (rec->type_code == 19) { // X25
        if (rec->rdata_count != 1) {
            if (ctx && ctx->err_out) {
                ctx->err_out->error_message = "X25 requires exactly 1 parameter";
                ctx->err_out->error_offset = rec->type - buf;
                ctx->err_out->token_length = strlen(rec->type);
            }
            return -1;
        }
    } else if (rec->type_code == 20) { // ISDN
        if (rec->rdata_count < 1 || rec->rdata_count > 2) {
            if (ctx && ctx->err_out) {
                ctx->err_out->error_message = "ISDN requires 1 or 2 parameters";
                ctx->err_out->error_offset = rec->type - buf;
                ctx->err_out->token_length = strlen(rec->type);
            }
            return -1;
        }
    } else if (rec->type_code == 27) { // GPOS
        if (rec->rdata_count != 3) {
            if (ctx && ctx->err_out) {
                ctx->err_out->error_message = "GPOS requires exactly 3 parameters";
                ctx->err_out->error_offset = rec->type - buf;
                ctx->err_out->token_length = strlen(rec->type);
            }
            return -1;
        }
    }
  }
  if (p < end)
    goto STATE_START_LINE;
DONE:
  return arena->count;
}

void zone_arena_init(zone_arena_t *arena) {
  arena->records_cap = 0;
  arena->records = NULL;
  arena->data_pool_count = 0;
  arena->current_pool_cap = 0;
  arena->current_pool_idx = 0;
  arena->count = 0;
  arena->file_buf_count = 0;
  arena->hash_size = 0;
  arena->hash_table = NULL;
  atomic_init(&arena->reader_count, 0);
}
void zone_arena_free_include_buffers(zone_arena_t *arena) {
  for (int i = 0; i < arena->file_buf_count; i++) {
    free(arena->file_bufs[i]);
    free(arena->display_bufs[i]);
    free(arena->file_paths[i]);
  }
  arena->file_buf_count = 0;
}

void zone_arena_destroy(zone_arena_t *arena) {
  free(arena->records);
  for (int i = 0; i < arena->data_pool_count; i++)
    free(arena->data_pools[i]);
  free(arena->hash_table);
  zone_arena_free_include_buffers(arena);
}
uint32_t calc_fnv1a_str(const char *str) {
  uint32_t hash = 2166136261u;
  for (const char *p = str; *p; p++) {
    uint8_t c = *p;
    if (c >= 'A' && c <= 'Z')
      c |= 0x20;
    hash ^= c;
    hash *= 16777619u;
  }
  return hash;
}
static size_t next_pow2(size_t n) {
  size_t p = 256;
  while (p < n)
    p <<= 1;
  return p;
}
void build_zone_index(zone_arena_t *arena) {
  if (arena->hash_table) {
    free(arena->hash_table);
    arena->hash_table = NULL;
  }
  arena->hash_size = next_pow2(arena->count * 2);
  arena->hash_table = malloc(sizeof(int) * arena->hash_size);
  for (size_t i = 0; i < arena->hash_size; i++)
    arena->hash_table[i] = -1;
  for (int i = (int)arena->count - 1; i >= 0; i--) {
    dns_record_t *rec = &arena->records[i];
    if (!rec->name)
      continue;
    uint32_t hash = calc_fnv1a_str(rec->name);
    size_t idx = hash & (arena->hash_size - 1);
    rec->next_record = arena->hash_table[idx];
    arena->hash_table[idx] = i;
  }
}


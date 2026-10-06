#include "dns_zone_parser.h"
#include "dns_utils.h"
#include <ctype.h>

static void unescape_string_in_place(char *str) {
    if (!str) return;
    char *read = str;
    char *write = str;
    while (*read) {
        if (*read == '\\' && *(read + 1)) {
            read++;
            // RFC 1035 §5.1: \DDD は 000 から 255 までの 10 進数 3 桁
            if (isdigit((unsigned char)*read) && 
                isdigit((unsigned char)*(read+1)) && 
                isdigit((unsigned char)*(read+2))) {
                
                int val = (*read - '0') * 100 + (*(read+1) - '0') * 10 + (*(read+2) - '0');
                if (val <= 255) {
                    *write++ = (char)val;
                    read += 3;
                    continue;
                }
            }
            *write++ = *read++;
        } else {
            *write++ = *read++;
        }
    }
    *write = '\0';
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define LOG_EMERG   0
#define LOG_ALERT   1
#define LOG_CRIT    2
#define LOG_ERR     3
#define LOG_WARNING 4
#define LOG_NOTICE  5
#define LOG_INFO    6
#define LOG_DEBUG   7
#define syslog(prio, ...) ((void)0)
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <strings.h>
#endif
#include "dns_utils.h"

#define IS_SPACE(c) ((c) == ' ' || (c) == '\t')
#define IS_NEWLINE(c) ((c) == '\n' || (c) == '\r')
#define MAX_FIELDS 512


void *arena_alloc(zone_arena_t *arena, size_t size) {
  // 追加: sizeそのものへの上限、および加算オーバーフローチェック
  if (size == 0 || size > (64 * 1024 * 1024)) return NULL; // 単一アロケーション上限
  if (arena->current_pool_idx > SIZE_MAX - size) return NULL; // 加算オーバーフロー防止

  // 16バイトアライメント (max_align_t 相当) を確保
  size_t aligned_idx = (arena->current_pool_idx + 15) & ~(size_t)15;
  if (aligned_idx < arena->current_pool_idx) return NULL;
  size_t aligned_size = (size + 15) & ~(size_t)15;
  if (aligned_size < size) return NULL;
  if (aligned_idx > SIZE_MAX - aligned_size) return NULL;

  if (aligned_idx + aligned_size > arena->current_pool_cap ||
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
    if (aligned_size > arena->current_pool_cap)
      arena->current_pool_cap = aligned_size + (1024 * 1024);
    arena->data_pools[arena->data_pool_count] = malloc(arena->current_pool_cap);
    if (!arena->data_pools[arena->data_pool_count])
      return NULL;
    aligned_idx = 0;
    arena->data_pool_count++;
  }
  void *ptr =
      &arena->data_pools[arena->data_pool_count - 1][aligned_idx];
  arena->current_pool_idx = aligned_idx + aligned_size;
  return ptr;
}

char *arena_strdup(zone_arena_t *arena, const char *str) {
  if (!str)
    return NULL;
  size_t len = strlen(str);
  char *dup = arena_alloc(arena, len + 1);
  if (dup) {
    memcpy(dup, str, len);
    dup[len] = '\0';
  }
  return dup;
}

bool compare_records(const dns_record_t *a, const dns_record_t *b, bool ignore_ttl) {
  if (a->type_code != b->type_code) return false;
  if ((a->name == NULL) != (b->name == NULL)) return false;
  if (a->name && b->name && strcasecmp(a->name, b->name) != 0) return false;
  if (!ignore_ttl) {
    if ((a->ttl == NULL) != (b->ttl == NULL)) return false;
    if (a->ttl && b->ttl && strcmp(a->ttl, b->ttl) != 0) return false;
  }
  if (a->tinydns_ttd != b->tinydns_ttd) return false;
  if (a->tinydns_ttl_countdown != b->tinydns_ttl_countdown) return false;
  if (a->tinydns_loc[0] != b->tinydns_loc[0] || a->tinydns_loc[1] != b->tinydns_loc[1]) return false;
  if ((a->ecs_subnet_tag == NULL) != (b->ecs_subnet_tag == NULL)) return false;
  if (a->ecs_subnet_tag && b->ecs_subnet_tag && strcasecmp(a->ecs_subnet_tag, b->ecs_subnet_tag) != 0) return false;
  if ((a->bind_location_tag == NULL) != (b->bind_location_tag == NULL)) return false;
  if (a->bind_location_tag && b->bind_location_tag && strcasecmp(a->bind_location_tag, b->bind_location_tag) != 0) return false;
  if (a->rdata_count != b->rdata_count) return false;
  for (int i = 0; i < a->rdata_count; i++) {
    if ((a->rdata[i] == NULL) != (b->rdata[i] == NULL)) return false;
    if (a->rdata[i] && b->rdata[i] && strcmp(a->rdata[i], b->rdata[i]) != 0) return false;
  }
  if (a->generic_len != b->generic_len) return false;
  if (a->generic_len > 0 && memcmp(a->generic_data, b->generic_data, a->generic_len) != 0) return false;
  return true;
}

bool record_exists_in_arena(zone_arena_t *arena, const dns_record_t *target) {
  if (!arena->hash_table) return false;
  if (!target->name) return false;
  uint32_t hash = calc_fnv1a_str(target->name);
  size_t idx = hash & (arena->hash_size - 1);
  for (int i = arena->hash_table[idx]; i != -1; i = arena->records[i].next_record) {
    if (compare_records(&arena->records[i], target, false)) return true;
  }
  return false;
}

static char *expand_domain_name_raw(char *name, const char *origin,
                                    zone_arena_t *arena) {
  if (!name)
    return name;
  size_t n_len = strlen(name);
  if (n_len > 0 && name[n_len - 1] == '.') {
    // Check if the dot is escaped by counting preceding backslashes
    int bs_count = 0;
    for (int i = (int)n_len - 2; i >= 0 && name[i] == '\\'; i--) {
        bs_count++;
    }
    if (bs_count % 2 == 0) {
        return name; // FQDN
    }
  }
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
  if (!origin || strcmp(origin, ".") == 0 || origin[0] == '\0') {
    char *fqdn = (char *)arena_alloc(arena, n_len + 2);
    if (!fqdn)
      return name;
    memcpy(fqdn, name, n_len);
    fqdn[n_len] = '.';
    fqdn[n_len + 1] = '\0';
    return fqdn;
  }
  size_t o_len = strlen(origin);
  bool origin_has_dot = false;
  if (o_len > 0 && origin[o_len - 1] == '.') {
      int bs_count = 0;
      for (int i = (int)o_len - 2; i >= 0 && origin[i] == '\\'; i--) {
          bs_count++;
      }
      if (bs_count % 2 == 0) {
          origin_has_dot = true;
      }
  }
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

/* origin を補った名前を、クエリ名・転送で受けた名前と同じ正規形 (dns_wire.h) にする (R-29)。
 * RFC 1035 §5.1: \X と \DDD はそのオクテットを表す。"sp\032ace" と "c\(p" はそれぞれ
 * "sp\032ace"、"c(p" に、"\065bc" は "Abc" になる。正規化できない名前 (不正なエスケープ、
 * 空ラベル、長すぎる名前) はそのまま返し、validate_domain_name_length() がエラーにする。 */
static char *expand_domain_name(char *name, const char *origin, zone_arena_t *arena) {
  char *fqdn = expand_domain_name_raw(name, origin, arena);
  if (!fqdn || strcmp(fqdn, "@") == 0) return fqdn;
  char norm[DNS_NAME_TEXT_SIZE];
  size_t n = dns_name_normalize(fqdn, norm, sizeof(norm));
  if (n == (size_t)-1 || strcmp(norm, fqdn) == 0) return fqdn;
  char *copy = (char *)arena_alloc(arena, n + 1);
  if (!copy) return fqdn;
  memcpy(copy, norm, n + 1);
  return copy;
}

// RFC 1035 §3.1: 各ラベルは63オクテット以下、ドメイン名全体は255オクテット以下を検証
static bool validate_domain_name_length(const char *fqdn, parse_error_t *err_out,
                                        const char *field_pos_in_buf, const char *buf) {
    if (!fqdn) return true;
    size_t total_wire_len = 1; // 終端の0バイト分
    size_t label_len = 0;
    for (const char *p = fqdn; *p; p++) {
        if (*p == '\\') {
            if (*(p + 1) != '\0') {
                if (isdigit((unsigned char)*(p + 1)) &&
                    isdigit((unsigned char)*(p + 2)) &&
                    isdigit((unsigned char)*(p + 3))) {
                    p += 3;
                } else {
                    p++;
                }
            }
            label_len++;
            total_wire_len++;
            continue;
        }
        if (*p == '.') {
            if (label_len > 63) {
                if (err_out) {
                    err_out->error_message = "Domain name label exceeds 63 octets (RFC 1035 §3.1)";
                    if (buf && field_pos_in_buf) err_out->error_offset = (size_t)(field_pos_in_buf - buf);
                    err_out->token_length = label_len;
                }
                return false;
            }
            if (label_len > 0) {
                total_wire_len += 1; // ラベル長バイト分
            }
            label_len = 0;
            continue;
        }
        label_len++;
        total_wire_len++;
    }
    if (label_len > 63) {
        if (err_out) {
            err_out->error_message = "Domain name label exceeds 63 octets (RFC 1035 §3.1)";
            if (buf && field_pos_in_buf) err_out->error_offset = (size_t)(field_pos_in_buf - buf);
            err_out->token_length = label_len;
        }
        return false;
    }
    if (label_len > 0) {
        total_wire_len += 1;
    }
    if (total_wire_len > 255) {
        if (err_out) {
            err_out->error_message = "Domain name exceeds 255 octets total (RFC 1035 §3.1)";
            if (buf && field_pos_in_buf) err_out->error_offset = (size_t)(field_pos_in_buf - buf);
            err_out->token_length = strlen(fqdn);
        }
        return false;
    }
    /* 長さ以外の理由で正規形にできない名前 (RFC 1035 §5.1 の \DDD が 255 を超える、
     * 末尾の '\'、空ラベル "a..b") も、ワイヤ形式に書けないのでロード時に弾く。 */
    char norm[DNS_NAME_TEXT_SIZE];
    if (strcmp(fqdn, "@") != 0 && dns_name_normalize(fqdn, norm, sizeof(norm)) == (size_t)-1) {
        if (err_out) {
            err_out->error_message = "Invalid domain name (bad escape or empty label, RFC 1035 §5.1)";
            if (buf && field_pos_in_buf) err_out->error_offset = (size_t)(field_pos_in_buf - buf);
            err_out->token_length = strlen(fqdn);
        }
        return false;
    }
    return true;
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

/* 1つのゾーンの読み込み中に、$INCLUDE と $GENERATE をまたいで共有する状態。
 * origin だけは $INCLUDE ごとに別 (RFC 1035 §5.1: $INCLUDE は親ファイルの origin を変えない)。 */
typedef struct {
    char **origin_io;
    char **ttl_io;       /* $TTL (RFC 2308 §4)。TTL の無い SOA の MINIMUM もここに入る (BIND と同じ) */
    char **last_ttl_io;  /* 最後に明示された TTL (RFC 1035 §5.1) */
    char **ecs_tag_io;
    char **loc_tag_io;
} zone_parse_state_t;

static int parse_zone_buffer(char *buf, size_t size, zone_arena_t *arena, parse_context_t *ctx,
                             const zone_parse_state_t *st, bool finalize);

static int process_include(char **fields, int field_idx, zone_arena_t *arena,
                            parse_context_t *ctx, const zone_parse_state_t *st, char *cur_buf) {
    if (!ctx || !ctx->load_file_cb || !ctx->base_dir) {
        if (ctx && ctx->err_out) ctx->err_out->error_message = "$INCLUDE is not available (no file loader configured by the caller)";
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

    if (ctx->visited_count >= ctx->visited_cap) {
        if (ctx->err_out) ctx->err_out->error_message = "Ancestor path stack exhausted";
        free(resolved);
        return -1;
    }

    dev_t cur_dev = 0;
    ino_t cur_ino = 0;
    char *file_content = ctx->load_file_cb ? ctx->load_file_cb(ctx, resolved, &cur_dev, &cur_ino) : NULL;
    if (!file_content) {
        if (ctx->err_out) {
            ctx->err_out->error_message = "$INCLUDE file could not be read or fstat failed";
            ctx->err_out->error_offset = (size_t)(fields[1] - cur_buf);
            ctx->err_out->token_length = strlen(fields[1]);
        }
        free(resolved);
        return -1;
    }

    // --- 循環検出: 祖先スタックの中に同じinode(dev, ino)があれば拒否 ---
    for (int i = 0; i < ctx->visited_count; i++) {
        if (ctx->visited_devs && ctx->visited_inos && 
            ctx->visited_devs[i] == cur_dev && ctx->visited_inos[i] == cur_ino) {
            if (ctx->err_out) {
                ctx->err_out->error_message = "Circular $INCLUDE detected";
                ctx->err_out->error_offset = (size_t)(fields[1] - cur_buf);
                ctx->err_out->token_length = strlen(fields[1]);
            }
            free(file_content);
            free(resolved);
            return -1;
        }
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

    /* RFC 1035 §5.1: $INCLUDE の origin 引数も、相対名なら現在の origin を補う (R-22 d) */
    char *child_origin = *st->origin_io;
    if (field_idx > 2) {
        child_origin = expand_domain_name(fields[2], *st->origin_io, arena);
        if (!validate_domain_name_length(child_origin, ctx->err_out, fields[2], cur_buf))
            return -1;
    }

    ctx->visited_paths[ctx->visited_count] = resolved;
    if (ctx->visited_devs) ctx->visited_devs[ctx->visited_count] = cur_dev;
    if (ctx->visited_inos) ctx->visited_inos[ctx->visited_count] = cur_ino;
    ctx->visited_count++;

    parse_context_t child_ctx = *ctx;
    child_ctx.default_origin = child_origin;
    child_ctx.current_depth = ctx->current_depth + 1;
    zone_parse_state_t child_st = *st;
    child_st.origin_io = &child_origin;

    int rc = parse_zone_buffer(file_content, strlen(file_content), arena, &child_ctx, &child_st, false);

    if (rc < 0 && ctx && ctx->err_out && !ctx->err_out->file_path) {
        ctx->err_out->file_path = resolved;
    }

    ctx->visited_count--;

    return rc;
}

dns_record_t *arena_alloc_record(zone_arena_t *arena, parse_context_t *ctx, const char *err_pos, const char *buf) {
    if (arena->count >= arena->records_cap) {
        size_t new_cap = arena->records_cap == 0 ? 16 : arena->records_cap * 2;
        if (new_cap > SIZE_MAX / sizeof(dns_record_t)) {
            if (ctx && ctx->err_out) {
                ctx->err_out->error_message = "Out of memory / Integer overflow";
                ctx->err_out->error_offset = (size_t)(err_pos - buf);
                ctx->err_out->token_length = 1;
            }
            return NULL;
        }
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
    dns_record_t *rec = &arena->records[arena->count++];
    memset(rec, 0, sizeof(dns_record_t));
    return rec;
}

/* クラス欄のニーモニック (RFC 1035 §5.1, RFC 3597 §5)。大文字小文字は区別しない (RFC 1035 §2.3.3)。
 * NONE/ANY も「クラス欄」としては認識し、ゾーンデータに使えるかは呼び出し側で判定する。 */
static bool parse_class_token(const char *s, uint16_t *out) {
    if (strcasecmp(s, "IN") == 0) { *out = 1; return true; }
    if (strcasecmp(s, "CH") == 0) { *out = 3; return true; }
    if (strcasecmp(s, "HS") == 0) { *out = 4; return true; }
    if (strcasecmp(s, "NONE") == 0) { *out = 254; return true; }
    if (strcasecmp(s, "ANY") == 0) { *out = 255; return true; }
    if (strncasecmp(s, "CLASS", 5) == 0 && s[5] != '\0') {
        unsigned long v = 0;
        for (const char *d = s + 5; *d; d++) {
            if (*d < '0' || *d > '9') return false;
            v = v * 10 + (unsigned long)(*d - '0');
            if (v > 65535) return false;
        }
        *out = (uint16_t)v;
        return true;
    }
    return false;
}

/* ゾーンデータとして置けないクラス: 0 (予約)、NONE/ANY (QCLASS と UPDATE 専用。RFC 6895 §3.2、
 * RFC 2136 §2.4)、KariDNS が内部で使う私用クラス (ゾーンファイルから注入させない)。 */
static bool class_allowed_in_zone_data(uint16_t cls) {
    return cls != 0 && cls != 254 && cls != 255 && cls != DNS_CLASS_KARIDNS_EXT;
}

static void upcase_in_place(char *s) {
    for (; *s; s++) *s = (char)toupper((unsigned char)*s);
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
    if (endptr != dash || endptr == range_str) {
        if (err_out) err_out->error_message = "$GENERATE invalid start value";
        return -1;
    }
    const char *stop_str = dash + 1;
    uint64_t stop = strtoull(stop_str, &endptr, 10);
    if (endptr == stop_str) {
        if (err_out) err_out->error_message = "$GENERATE invalid stop value";
        return -1;
    }
    uint64_t step = 1;
    if (*endptr == '/') {
        const char *step_str = endptr + 1;
        step = strtoull(step_str, &endptr, 10);
        if (endptr == step_str) {
            if (err_out) err_out->error_message = "$GENERATE invalid step value";
            return -1;
        }
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

/* BIND の $GENERATE の n/N 修飾子 (lib/dns/master.c nibbles()): 値を下位ニブルから順に 1 桁ずつ
 * '.' で区切って書く (逆引きの ip6.arpa 名を作るため)。width は '.' も含めた文字数で、足りなければ 0 を補う。 */
static int generate_nibbles(char *out, size_t out_cap, int width, char mode, uint64_t value) {
    static const char hex_lc[] = "0123456789abcdef", hex_uc[] = "0123456789ABCDEF";
    const char *hex = (mode == 'n') ? hex_lc : hex_uc;
    size_t n = 0;
    do {
        if (n + 1 >= out_cap) return -1;
        out[n++] = hex[value & 0x0f];
        value >>= 4;
        if (width > 0) width--;
        if (width > 0 || value != 0) {
            if (n + 1 >= out_cap) return -1;
            out[n++] = '.';
            if (width > 0) width--;
        }
    } while (value != 0 || width > 0);
    out[n] = '\0';
    return (int)n;
}

/* BIND の genname() と同じ規則で $GENERATE の lhs / rhs を展開する。
 * "$" は値、"$$" は "$"、"${offset[,width[,base]]}" の base は d o x X n N。
 * '\' はその次の 1 文字と一緒にそのまま写す ("\$" は後で名前・RDATA として読むときに '$' になる)。 */
static size_t expand_generate_template(const char *tmpl, uint64_t value, char *out, size_t out_cap, parse_error_t *err_out) {
    size_t out_len = 0;
    for (const char *p = tmpl; *p; ) {
        if (*p == '\\') {
            size_t n = (p[1] != '\0') ? 2 : 1;
            if (out_len + n > out_cap) return (size_t)-1;
            memcpy(out + out_len, p, n);
            out_len += n;
            p += n;
            continue;
        }
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
                        p++;
                        if (*p == '\0') {
                            if (err_out) err_out->error_message = "$GENERATE malformed ${...} substitution";
                            return (size_t)-1;
                        }
                        base = *p++;
                    }
                }
                if (*p != '}') {
                    if (err_out) err_out->error_message = "$GENERATE malformed ${...} substitution";
                    return (size_t)-1;
                }
                p++;
            }
            if (base != 'd' && base != 'o' && base != 'x' && base != 'X' && base != 'n' && base != 'N') {
                if (err_out) err_out->error_message = "$GENERATE base must be one of d,o,x,X,n,N";
                return (size_t)-1;
            }

            int64_t v = (int64_t)value + offset;
            char numbuf[160];
            int n;
            if (base == 'n' || base == 'N') {
                if (v < 0) {
                    if (err_out) err_out->error_message = "$GENERATE nibble value must not be negative";
                    return (size_t)-1;
                }
                n = generate_nibbles(numbuf, sizeof(numbuf), width, base, (uint64_t)v);
            } else {
                const char *fmt = (base == 'd') ? "%0*lld" : (base == 'o') ? "%0*llo" : (base == 'x') ? "%0*llx" : "%0*llX";
                n = (base == 'd') ? snprintf(numbuf, sizeof(numbuf), fmt, width, (long long)v)
                                  : snprintf(numbuf, sizeof(numbuf), fmt, width, (unsigned long long)v);
            }
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

static void generate_error(parse_context_t *ctx, const char *msg, const char *tok, const char *cur_buf) {
    if (!ctx || !ctx->err_out) return;
    if (msg) ctx->err_out->error_message = msg;
    ctx->err_out->error_offset = (size_t)(tok - cur_buf);
    ctx->err_out->token_length = strlen(tok);
}

/* 展開した lhs は 1 行の先頭のオーナー名として読み直すので、1 トークンでなければならない */
static bool generate_lhs_is_single_token(const char *s) {
    if (s[0] == '\0' || s[0] == '$') return false;
    for (; *s; s++) {
        if (*s == '\\') {
            if (s[1] == '\0') return false;
            s++;
            continue;
        }
        if (IS_SPACE(*s) || IS_NEWLINE(*s) || *s == '"' || *s == ';' || *s == '(' || *s == ')') return false;
    }
    return true;
}

/* $GENERATE range lhs [ttl] [class] type rhs (BIND の構文。ttl と class は順不同)。
 * rhs は 1 フィールドで、空白を含む RDATA は引用符で囲む (例: MX "10 mail$")。
 * 値ごとに "lhs [ttl] [class] type rhs" の 1 行を作り、通常のレコード行と同じ処理に通す
 * (BIND も展開した rhs を通常の RDATA として読む)。そのため型の制限は無く、検証・エスケープ・
 * TTL の既定値・$ECS-SUBNET / $LOCATION のタグも通常の行と同じになる (R-22 e, D-18)。 */
static int process_generate(char **fields, int field_idx, zone_arena_t *arena,
                             parse_context_t *ctx, const zone_parse_state_t *st, const char *cur_buf) {
    if (field_idx < 5) {
        generate_error(ctx, "$GENERATE requires range lhs [ttl] [class] type rhs", fields[0], cur_buf);
        return -1;
    }
    parse_error_t local_err = {0};
    generate_range_t range;
    if (parse_generate_range(fields[1], &range, &local_err) != 0) {
        generate_error(ctx, local_err.error_message, fields[1], cur_buf);
        return -1;
    }

    const char *lhs_tmpl = fields[2];
    const char *ttl_str = NULL, *class_str = NULL, *type_str = NULL, *rhs_tmpl = NULL;
    int i = 3;
    for (; i < field_idx; i++) {
        uint16_t cls;
        if (!ttl_str && fields[i][0] >= '0' && fields[i][0] <= '9') {
            ttl_str = fields[i];
        } else if (!class_str && parse_class_token(fields[i], &cls)) {
            class_str = fields[i];
        } else {
            type_str = fields[i];
            break;
        }
    }
    if (type_str && i + 1 < field_idx) rhs_tmpl = fields[i + 1];
    if (!type_str || !rhs_tmpl) {
        generate_error(ctx, "$GENERATE requires range lhs [ttl] [class] type rhs", fields[0], cur_buf);
        return -1;
    }
    if (i + 2 < field_idx) {
        generate_error(ctx, "$GENERATE rhs must be a single field (quote an rhs that contains spaces)",
                       fields[i + 2], cur_buf);
        return -1;
    }
    if (get_type_code(type_str) == 0) {
        generate_error(ctx, "Unknown record type", type_str, cur_buf);
        return -1;
    }

    char lhs_buf[DNS_NAME_TEXT_SIZE], rhs_buf[4096];
    for (uint64_t v = range.start; v <= range.stop; v += range.step) {
        size_t lhs_len = expand_generate_template(lhs_tmpl, v, lhs_buf, sizeof(lhs_buf), &local_err);
        if (lhs_len == (size_t)-1) {
            generate_error(ctx, local_err.error_message ? local_err.error_message : "$GENERATE lhs expansion failed",
                           fields[2], cur_buf);
            return -1;
        }
        if (!generate_lhs_is_single_token(lhs_buf)) {
            generate_error(ctx, "$GENERATE lhs must expand to a single owner name", fields[2], cur_buf);
            return -1;
        }
        size_t rhs_len = expand_generate_template(rhs_tmpl, v, rhs_buf, sizeof(rhs_buf), &local_err);
        if (rhs_len == (size_t)-1) {
            generate_error(ctx, local_err.error_message ? local_err.error_message : "$GENERATE rhs expansion failed",
                           rhs_tmpl, cur_buf);
            return -1;
        }

        /* レコードは行バッファ内の文字列を指すので、行はアリーナに置く */
        size_t line_cap = lhs_len + rhs_len + strlen(type_str) + (ttl_str ? strlen(ttl_str) : 0) +
                          (class_str ? strlen(class_str) : 0) + 8;
        char *line = arena_alloc(arena, line_cap);
        if (!line) {
            generate_error(ctx, "Out of memory", fields[0], cur_buf);
            return -1;
        }
        int line_len = snprintf(line, line_cap, "%s %s%s%s%s%s %s\n", lhs_buf,
                                ttl_str ? ttl_str : "", ttl_str ? " " : "",
                                class_str ? class_str : "", class_str ? " " : "", type_str, rhs_buf);
        if (line_len < 0 || (size_t)line_len >= line_cap) {
            generate_error(ctx, "$GENERATE line too long", fields[0], cur_buf);
            return -1;
        }

        /* 生成した行で origin が変わることは無いが、親の origin は書き換えさせない */
        char *gen_origin = *st->origin_io;
        zone_parse_state_t gen_st = *st;
        gen_st.origin_io = &gen_origin;
        if (parse_zone_buffer(line, (size_t)line_len, arena, ctx, &gen_st, false) < 0) {
            /* エラー位置は生成した行ではなく、$GENERATE の行を指す */
            generate_error(ctx, NULL, fields[0], cur_buf);
            return -1;
        }

        if (range.stop - v < range.step) break;
    }
    return 0;
}

int parse_zone_fast(char *buf, size_t size, zone_arena_t *arena, parse_context_t *ctx) {
  char *origin = ctx ? (char *)ctx->default_origin : NULL;
  char *local_ttl_storage = NULL;
  char *last_ttl = NULL;
  char *local_ecs_tag_storage = NULL;
  char *local_loc_tag_storage = NULL;
  zone_parse_state_t st = {
    .origin_io = &origin,
    .ttl_io = (ctx && ctx->shared_ttl_io) ? ctx->shared_ttl_io : &local_ttl_storage,
    .last_ttl_io = &last_ttl,
    .ecs_tag_io = (ctx && ctx->shared_ecs_tag_io) ? ctx->shared_ecs_tag_io : &local_ecs_tag_storage,
    .loc_tag_io = (ctx && ctx->shared_loc_tag_io) ? ctx->shared_loc_tag_io : &local_loc_tag_storage,
  };
  return parse_zone_buffer(buf, size, arena, ctx, &st, true);
}

/* finalize: 最上位のファイルの読み込みの最後に、全レコードの前処理キャッシュを作る。
 * $INCLUDE と $GENERATE の行は最上位がまとめて処理するので false で呼ぶ。 */
static int parse_zone_buffer(char *buf, size_t size, zone_arena_t *arena, parse_context_t *ctx,
                             const zone_parse_state_t *st, bool finalize) {
  char *prev_owner = NULL;
  char **prev_owner_io = &prev_owner;
  char **origin_io = st->origin_io;
  char **default_ttl_str_io = st->ttl_io;
  char **ecs_tag_io = st->ecs_tag_io;
  char **loc_tag_io = st->loc_tag_io;
  if (!buf || size == 0 || !arena)
    return -1;
  char *p = buf, *end = buf + size;
  int in_parens = 0, in_quotes = 0, field_idx = 0;
  bool is_tag_def_line = false;
  char *fields[MAX_FIELDS], *token_start = NULL;

STATE_START_LINE:
  if (p >= end)
    goto DONE;
  field_idx = 0;
  in_quotes = 0;
  is_tag_def_line = false;
  char *scan = p;
  while (scan < end && IS_SPACE(*scan)) scan++;
  if (scan < end && *scan == '$') {
    if ((end - scan >= 13 && strncasecmp(scan, "$LOCATION-TAG", 13) == 0 && (scan + 13 >= end || IS_SPACE(scan[13]))) ||
        (end - scan >= 15 && strncasecmp(scan, "$ECS-SUBNET-TAG", 15) == 0 && (scan + 15 >= end || IS_SPACE(scan[15])))) {
      is_tag_def_line = true;
    }
  }
  if (IS_SPACE(*p)) {
    if (*prev_owner_io)
      fields[field_idx++] = *prev_owner_io;
    goto SKIP_WHITESPACE;
  }
STATE_FIND_TOKEN:
  if (is_tag_def_line && p < end && (*p == '{' || *p == '}' || *p == ';')) {
    p++;
    goto STATE_FIND_TOKEN;
  }
  if (p >= end) {
    if (in_parens) {
      if (ctx && ctx->err_out) {
        ctx->err_out->error_message = "Unbalanced parenthesis: '(' was never closed before end of file";
        ctx->err_out->error_offset = (size_t)(buf ? (p - buf) : 0);
        ctx->err_out->token_length = 0;
      }
      return -1;
    }
    goto PROCESS_RECORD;
  }
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
    if (in_parens) {
      if (ctx && ctx->err_out) {
        ctx->err_out->error_message = "Nested parentheses are not allowed in zone file records";
        ctx->err_out->error_offset = (size_t)(p - buf);
        ctx->err_out->token_length = 1;
      }
      return -1;
    }
    in_parens = 1;
    *p++ = '\0';
    goto STATE_FIND_TOKEN;
  }
  if (*p == ')') {
    if (!in_parens) {
      if (ctx && ctx->err_out) {
        ctx->err_out->error_message = "Unmatched ')' with no preceding '(' in zone file record";
        ctx->err_out->error_offset = (size_t)(p - buf);
        ctx->err_out->token_length = 1;
      }
      return -1;
    }
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
      if (IS_SPACE(*p) || IS_NEWLINE(*p) || *p == ';' || *p == '(' || *p == ')' ||
          (is_tag_def_line && (*p == '{' || *p == '}')))
        break;
    } else {
      if (IS_NEWLINE(*p)) {
        if (ctx && ctx->err_out) {
            ctx->err_out->error_message = "Unterminated quoted string (closing '\"' missing before end of line)";
            ctx->err_out->error_offset = token_start - buf;
            ctx->err_out->token_length = (size_t)(p - token_start);
        }
        return -1;
      }
    }
    p++;
  }

  if (p >= end && in_quotes) {
    if (ctx && ctx->err_out) {
        ctx->err_out->error_message = "Unterminated quoted string (missing closing '\"' at end of file)";
        ctx->err_out->error_offset = token_start - buf;
        ctx->err_out->token_length = (size_t)(p - token_start);
    }
    return -1;
  }

          if (field_idx < MAX_FIELDS) {
            fields[field_idx++] = token_start;
          } else {
            if (ctx && ctx->err_out) {
                ctx->err_out->error_message = "Too many fields in a single record (exceeds MAX_FIELDS)";
                ctx->err_out->error_offset = token_start - buf;
                ctx->err_out->token_length = (size_t)(p - token_start);
            }
            return -1;
          }
          
          // ファイル末尾に到達した場合でも、最後のトークンのクォートを除去する
          if (p >= end) {
            if (in_parens) {
              if (ctx && ctx->err_out) {
                ctx->err_out->error_message = "Unbalanced parenthesis: '(' was never closed before end of file";
                ctx->err_out->error_offset = (size_t)(buf ? (p - buf) : 0);
                ctx->err_out->token_length = 0;
              }
              return -1;
            }
            if (field_idx > 0) {
                if (fields[field_idx - 1][0] == '"') {
                    fields[field_idx - 1]++;
                    size_t t_len = strlen(fields[field_idx - 1]);
                    if (t_len > 0 && fields[field_idx - 1][t_len - 1] == '"')
                        fields[field_idx - 1][t_len - 1] = '\0';
                }
            }
            goto PROCESS_RECORD;
          }
  char delimiter = *p;
  *p++ = '\0';
  if (field_idx > 0) {
      if (fields[field_idx - 1][0] == '"') {
          fields[field_idx - 1]++;
          size_t t_len = strlen(fields[field_idx - 1]);
          if (t_len > 0 && fields[field_idx - 1][t_len - 1] == '"')
              fields[field_idx - 1][t_len - 1] = '\0';
      }
  }
  if (IS_SPACE(delimiter) || (is_tag_def_line && (delimiter == '{' || delimiter == '}')))
    goto SKIP_WHITESPACE;
  if (IS_NEWLINE(delimiter)) {
    if (in_parens)
      goto STATE_FIND_TOKEN;
    goto PROCESS_RECORD;
  }
  if (delimiter == '(') {
    if (in_parens) {
      if (ctx && ctx->err_out) {
        ctx->err_out->error_message = "Nested parentheses are not allowed in zone file records";
        ctx->err_out->error_offset = (size_t)(p - 1 - buf);
        ctx->err_out->token_length = 1;
      }
      return -1;
    }
    in_parens = 1;
    goto STATE_FIND_TOKEN;
  }
  if (delimiter == ')') {
    if (!in_parens) {
      if (ctx && ctx->err_out) {
        ctx->err_out->error_message = "Unmatched ')' with no preceding '(' in zone file record";
        ctx->err_out->error_offset = (size_t)(p - 1 - buf);
        ctx->err_out->token_length = 1;
      }
      return -1;
    }
    in_parens = 0;
    goto STATE_FIND_TOKEN;
  }
  if (delimiter == ';') {
    if (!is_tag_def_line) {
      char *nl = memchr(p, '\n', end - p);
      if (!nl) {
        p = end;
        goto PROCESS_RECORD;
      }
      p = nl;
      goto STATE_FIND_TOKEN;
    } else {
      goto STATE_FIND_TOKEN;
    }
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
    if (field_idx > 1) {
      /* RFC 1035 §5.1: 相対名の $ORIGIN は現在の origin を補って絶対名にする (R-22 d) */
      char *new_origin = expand_domain_name(fields[1], *origin_io, arena);
      if (!validate_domain_name_length(new_origin, ctx ? ctx->err_out : NULL, fields[1], buf)) {
        return -1;
      }
      *origin_io = new_origin;
    }
    if (p < end)
      goto STATE_START_LINE;
    goto DONE;
  }
    if (fields[0][0] == '$' && strcasecmp(fields[0], "$INCLUDE") == 0) {
        if (process_include(fields, field_idx, arena, ctx, st, buf) < 0)
            return -1;
        if (p < end)
            goto STATE_START_LINE;
        goto DONE;
    }
    if (fields[0][0] == '$' && strcasecmp(fields[0], "$GENERATE") == 0) {
        if (process_generate(fields, field_idx, arena, ctx, st, buf) != 0)
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
  if (fields[0][0] == '$' && strcasecmp(fields[0], "$ECS-SUBNET") == 0) {
    if (field_idx > 1) {
      if (fields[1][0] == '\0' || strcasecmp(fields[1], "none") == 0 || strcasecmp(fields[1], "default") == 0) {
        *ecs_tag_io = NULL;
      } else {
        *ecs_tag_io = arena_strdup(arena, fields[1]);
      }
    } else {
      *ecs_tag_io = NULL; /* タグ省略時はnone扱い */
    }
    if (p < end)
      goto STATE_START_LINE;
    goto DONE;
  }
  if (fields[0][0] == '$' && strcasecmp(fields[0], "$LOCATION") == 0) {
    if (field_idx > 1) {
      if (fields[1][0] == '\0' || strcasecmp(fields[1], "none") == 0 || strcasecmp(fields[1], "default") == 0) {
        *loc_tag_io = NULL;
      } else {
        *loc_tag_io = arena_strdup(arena, fields[1]);
      }
    } else {
      *loc_tag_io = NULL; /* タグ省略時はnone扱い */
    }
    if (p < end)
      goto STATE_START_LINE;
    goto DONE;
  }
  if (fields[0][0] == '$' && (strcasecmp(fields[0], "$LOCATION-TAG") == 0 || strcasecmp(fields[0], "$ECS-SUBNET-TAG") == 0)) {
    bool is_loc = (strcasecmp(fields[0], "$LOCATION-TAG") == 0);
    if (field_idx < 3) {
      if (ctx && ctx->err_out) {
        ctx->err_out->error_message = is_loc ? "$LOCATION-TAG requires tag name and at least one CIDR"
                                             : "$ECS-SUBNET-TAG requires tag name and at least one CIDR";
        ctx->err_out->error_offset = (size_t)(fields[0] - buf);
        ctx->err_out->token_length = strlen(fields[0]);
      }
      return -1;
    }
    const char *raw_tag = fields[1];
    while (*raw_tag == '{' || *raw_tag == ' ' || *raw_tag == '\t') raw_tag++;
    char clean_tag[64];
    strncpy(clean_tag, raw_tag, sizeof(clean_tag) - 1);
    clean_tag[sizeof(clean_tag) - 1] = '\0';
    size_t ctlen = strlen(clean_tag);
    while (ctlen > 0 && (clean_tag[ctlen-1] == '}' || clean_tag[ctlen-1] == ';' || clean_tag[ctlen-1] == ' ' || clean_tag[ctlen-1] == '\t')) {
      clean_tag[--ctlen] = '\0';
    }
    if (ctlen == 0) {
      if (ctx && ctx->err_out) {
        ctx->err_out->error_message = "Invalid empty tag name in tag definition";
        ctx->err_out->error_offset = (size_t)(fields[1] - buf);
        ctx->err_out->token_length = strlen(fields[1]);
      }
      return -1;
    }

    char *cidrs_found[MAX_FIELDS];
    int cidr_count = 0;
    for (int fi = 2; fi < field_idx; fi++) {
      char *raw_cidr = fields[fi];
      while (*raw_cidr == '{' || *raw_cidr == ' ' || *raw_cidr == '\t') raw_cidr++;
      char clean_cidr[128];
      strncpy(clean_cidr, raw_cidr, sizeof(clean_cidr) - 1);
      clean_cidr[sizeof(clean_cidr) - 1] = '\0';
      size_t clen = strlen(clean_cidr);
      while (clen > 0 && (clean_cidr[clen-1] == '}' || clean_cidr[clen-1] == ';' || clean_cidr[clen-1] == ' ' || clean_cidr[clen-1] == '\t')) {
        clean_cidr[--clen] = '\0';
      }
      if (clen == 0) continue;
      cidrs_found[cidr_count++] = strdup(clean_cidr);
    }
    if (cidr_count == 0) {
      if (ctx && ctx->err_out) {
        ctx->err_out->error_message = is_loc ? "$LOCATION-TAG requires at least one CIDR"
                                             : "$ECS-SUBNET-TAG requires at least one CIDR";
        ctx->err_out->error_offset = (size_t)(fields[0] - buf);
        ctx->err_out->token_length = strlen(fields[0]);
      }
      return -1;
    }
    ecs_tag_def_t **target_tags = is_loc ? &arena->bind_location_tags : &arena->bind_ecs_tags;
    int *target_count = is_loc ? &arena->bind_location_tag_count : &arena->bind_ecs_tag_count;
    ecs_tag_def_t *new_tags = realloc(*target_tags, sizeof(ecs_tag_def_t) * (*target_count + 1));
    if (!new_tags) {
      for (int c = 0; c < cidr_count; c++) free(cidrs_found[c]);
      if (ctx && ctx->err_out) ctx->err_out->error_message = "Out of memory";
      return -1;
    }
    *target_tags = new_tags;
    ecs_cidr_entry_t *cidrs = calloc(cidr_count, sizeof(ecs_cidr_entry_t));
    if (!cidrs) {
      for (int c = 0; c < cidr_count; c++) free(cidrs_found[c]);
      if (ctx && ctx->err_out) ctx->err_out->error_message = "Out of memory";
      return -1;
    }
    for (int c = 0; c < cidr_count; c++) {
      cidrs[c].cidr = cidrs_found[c];
      if (cidrs[c].cidr) {
        cidr_entry_parse(&cidrs[c].parsed, cidrs[c].cidr);
      }
    }
    (*target_tags)[*target_count].tag = strdup(clean_tag);
    (*target_tags)[*target_count].cidrs = cidrs;
    (*target_tags)[*target_count].cidr_count = cidr_count;
    (*target_count)++;

    if (p < end)
      goto STATE_START_LINE;
    goto DONE;
  }
    dns_record_t *rec = arena_alloc_record(arena, ctx, p, buf);
    if (!rec) return -1;
    rec->ecs_subnet_tag = *ecs_tag_io;
    rec->bind_location_tag = *loc_tag_io;
  rec->name = expand_domain_name(fields[0], *origin_io, arena);
  if (!rec->name) {
      if (ctx && ctx->err_out) {
          ctx->err_out->error_message = "Failed to allocate memory for domain name";
          ctx->err_out->error_offset = (size_t)(fields[0] - buf);
          ctx->err_out->token_length = strlen(fields[0]);
      }
      return -1;
  }
  if (!validate_domain_name_length(rec->name, ctx ? ctx->err_out : NULL, fields[0], buf)) {
      return -1;
  }
  *prev_owner_io = rec->name;
  rec->ttl = NULL;
  rec->class_str = NULL;
  rec->type = NULL;
  rec->rdata_count = 0;
  /* RFC 1035 §5.1: <owner> [<TTL>] [<class>] <type> <RDATA>。TTL と class は順不同で各 1 回
   * (2 つ目は型として読むので、BIND と同じく不正な型になる)。 */
  char *explicit_ttl = NULL;
  uint16_t class_val = 1; // クラス省略時は IN (BIND はゾーンのクラスを使う。KariDNS のゾーンは IN)
  int i = 1;
  while (i < field_idx) {
    char first_char = fields[i][0];
    uint16_t cls;
    if (!explicit_ttl && first_char >= '0' && first_char <= '9')
      explicit_ttl = fields[i];
    else if (!rec->class_str && parse_class_token(fields[i], &cls)) {
      if (!class_allowed_in_zone_data(cls)) {
        if (ctx && ctx->err_out) {
          ctx->err_out->error_message = "Class not allowed in zone data (0, NONE, ANY or a reserved class)";
          ctx->err_out->error_offset = (size_t)(fields[i] - buf);
          ctx->err_out->token_length = strlen(fields[i]);
        }
        return -1;
      }
      upcase_in_place(fields[i]);
      rec->class_str = fields[i];
      class_val = cls;
    } else {
      rec->type = fields[i];
      i++;
      break;
    }
    i++;
  }
  while (i < field_idx && rec->rdata_count < MAX_RDATA)
    rec->rdata[rec->rdata_count++] = fields[i++];

  if (i < field_idx) {
    if (ctx && ctx->err_out) {
      ctx->err_out->error_message = "Too many rdata fields on record (exceeds MAX_RDATA limit)";
      ctx->err_out->error_offset = (size_t)(fields[i] - buf);
      ctx->err_out->token_length = strlen(fields[i]);
    }
    return -1;
  }
    
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
  upcase_in_place(rec->type); // 型名は大文字小文字を区別しない (RFC 1035 §2.3.3)。以後は大文字の綴りで扱う

  /* Meta-types (OPT/TKEY/TSIG/IXFR/AXFR/MAILB/MAILA/ANY, and NXNAME per
   * RFC 9824) are QTYPE-only / synthesized-on-the-fly pseudo-RRs. They must
   * never be stored as zone data: doing so causes the record to be answered
   * and AXFR/IXFR'd to secondaries verbatim, and compliant secondaries such
   * as BIND and NSD will reject such a transfer with FORMERR. Reject the
   * zone load here instead of only warning at check-time. */
  if (is_meta_rrtype(rec->type_code)) {
    if (ctx && ctx->err_out) {
      ctx->err_out->error_message = "Meta-type RR must not be defined as zone data";
      ctx->err_out->error_offset = rec->type - buf;
      ctx->err_out->token_length = strlen(rec->type);
    }
    return -1;
  }
  
  /* TTL を省略したときの値 (R-22 c)。BIND (lib/dns/master.c) と同じ順で決める:
   * 明示した TTL > $TTL (RFC 2308 §4) > 最後に明示された TTL (RFC 1035 §5.1) >
   * TTL の手がかりが無い SOA ならその MINIMUM (以後の既定値になる) > 3600。 */
  if (explicit_ttl) {
    rec->ttl = explicit_ttl;
    *st->last_ttl_io = explicit_ttl;
  } else if (*default_ttl_str_io) {
    rec->ttl = *default_ttl_str_io;
  } else if (*st->last_ttl_io) {
    rec->ttl = *st->last_ttl_io;
  } else if (rec->type_code == 6 && rec->rdata_count == 7) {
    rec->ttl = rec->rdata[6];
    *default_ttl_str_io = rec->rdata[6];
  }
  rec->ttl_value = rec->ttl ? parse_ttl_value(rec->ttl) : 3600;
  rec->class_val = class_val;
  
  // A-1: Unescape fields appropriately
  // Owner name, type, class, ttl are handled without unescaping.
  // RDATA fields are unescaped UNLESS they are domain name fields.
  for (int j = 0; j < rec->rdata_count; j++) {
      bool is_domain_name = false;
      switch (rec->type_code) {
          case 2: case 3: case 4: case 5: case 7: case 8: case 9: case 12: case 23: case 39: // NS, MD, MF, CNAME, MB, MG, MR, PTR, NSAP-PTR, DNAME
              if (j == 0) is_domain_name = true;
              break;
          case 15: // MX
              if (j == 1) is_domain_name = true;
              break;
          case 6: // SOA
              if (j == 0 || j == 1) is_domain_name = true;
              break;
          case 33: // SRV
              if (j == 3) is_domain_name = true;
              break;
          case 35: // NAPTR
              if (j == 5) is_domain_name = true;
              break;
          case 14: case 17: // MINFO, RP
              if (j == 0 || j == 1) is_domain_name = true;
              break;
          case 18: case 36: case 21: case 107: // AFSDB, KX, RT, LP
              if (j == 1) is_domain_name = true;
              break;
          case 26: // PX
              if (j == 1 || j == 2) is_domain_name = true;
              break;
          case 30: // NXT (RFC 2535): rdata[0] = Next Domain Name
              if (j == 0) is_domain_name = true;
              break;
          case 38: // A6 (RFC 2874): rdata[2] = prefix name domain (prefix_len > 0 のときのみ)
              if (j == 2) is_domain_name = true;
              break;
          case 58: // TALINK: rdata[0]=prev, rdata[1]=next (両方ドメイン名)
              if (j == 0 || j == 1) is_domain_name = true;
              break;
          default:
              break;
      }
      if (!is_domain_name) {
          unescape_string_in_place(rec->rdata[j]);
      }
  }

  rec->generic_len = 0;
  rec->generic_data = NULL;
  /* EID (31) / NIMLOC (32) have no dedicated wire encoder; the server always serves them via the RFC 3597
   * generic form. dig's presentation for these undocumented types is a single bare hex token with no "\# len"
   * prefix, so accept that shape too by rewriting it into an equivalent "\# <len> <hex>" generic record. */
  if ((rec->type_code == 31 || rec->type_code == 32) && rec->rdata_count == 1 &&
      strcmp(rec->rdata[0], "\\#") != 0 && strcmp(rec->rdata[0], "#") != 0) {
    char hex_copy[512];
    /* snprintf rather than strlcpy: MinGW (Windows dag build) has no strlcpy */
    snprintf(hex_copy, sizeof(hex_copy), "%s", rec->rdata[0]);
    size_t hexlen = strlen(hex_copy);
    if (hexlen > 0 && (hexlen % 2) == 0 && hexlen < sizeof(hex_copy) &&
        strspn(hex_copy, "0123456789abcdefABCDEF") == hexlen && MAX_RDATA >= 3) {
      char lenbuf[16];
      snprintf(lenbuf, sizeof(lenbuf), "%zu", hexlen / 2);
      rec->rdata[0] = arena_strdup(arena, "\\#");
      rec->rdata[1] = arena_strdup(arena, lenbuf);
      rec->rdata[2] = arena_strdup(arena, hex_copy);
      rec->rdata_count = 3;
    }
  }
  if (rec->rdata_count >= 2 && (strcmp(rec->rdata[0], "\\#") == 0 || strcmp(rec->rdata[0], "#") == 0)) {
    /* RFC 3597 section 5: "\# <length> <hex rdata>". The declared length is a decimal number, the rdata is an
     * even number of hex digits (possibly split into several tokens) and its size MUST equal <length>. Anything
     * else used to be "repaired" silently (non-hex skipped, short data padded, long data cut off), which let a
     * malformed record be served as if it were valid (e.g. a 3-byte A record). */
    const char *len_tok = rec->rdata[1];
    size_t len_tok_len = strlen(len_tok);
    if (len_tok_len == 0 || len_tok_len > 5 || strspn(len_tok, "0123456789") != len_tok_len) {
      if (ctx && ctx->err_out) ctx->err_out->error_message = "Generic RDATA length (\\#) is not a decimal number";
      return -1;
    }
    long declared_len = atol(len_tok);
    if (declared_len < 0 || declared_len > 65535) {
      if (ctx && ctx->err_out) ctx->err_out->error_message = "Generic RDATA length (\\#) out of range (0-65535)";
      return -1;
    }
    size_t nibbles = 0;
    for (int j = 2; j < rec->rdata_count; j++) {
      for (const char *h = rec->rdata[j]; *h; h++) {
        if (hex_char_to_val(*h) < 0) {
          if (ctx && ctx->err_out) ctx->err_out->error_message = "Generic RDATA (\\#) contains a non-hexadecimal character";
          return -1;
        }
        nibbles++;
      }
    }
    if ((nibbles & 1) != 0) {
      if (ctx && ctx->err_out) ctx->err_out->error_message = "Generic RDATA (\\#) has an odd number of hex digits";
      return -1;
    }
    if (nibbles / 2 != (size_t)declared_len) {
      if (ctx && ctx->err_out) ctx->err_out->error_message = "Generic RDATA (\\#) length does not match the declared length";
      return -1;
    }
    /* Types whose RDATA has a fixed size must not be given in a different size, even in generic form. */
    {
      int fixed = -1;
      switch (rec->type_code) {
        case 1:   fixed = 4;  break;   /* A */
        case 28:  fixed = 16; break;   /* AAAA */
        case 108: fixed = 6;  break;   /* EUI48 */
        case 109: fixed = 8;  break;   /* EUI64 */
        case 105: fixed = 6;  break;   /* L32 */
        case 104: fixed = 10; break;   /* NID */
        case 106: fixed = 10; break;   /* L64 */
        default: break;
      }
      if (fixed >= 0 && declared_len != fixed) {
        if (ctx && ctx->err_out) ctx->err_out->error_message = "Generic RDATA (\\#) has the wrong length for this fixed-size record type";
        return -1;
      }
    }
    rec->generic_len = (uint16_t)declared_len;
    if (rec->generic_len > 0) {
      uint8_t *blob = (uint8_t *)arena_alloc(arena, rec->generic_len);
      if (blob) {
        size_t b_idx = 0;
        int high_nibble = -1;
        for (int j = 2; j < rec->rdata_count; j++) {
          for (char *h = rec->rdata[j]; *h; h++) {
            int val = hex_char_to_val(*h);
            if (high_nibble < 0)
              high_nibble = val;
            else {
              blob[b_idx++] = (uint8_t)((high_nibble << 4) | val);
              high_nibble = -1;
            }
          }
        }
        rec->generic_data = blob;
      }
    } else {
      rec->generic_data = (uint8_t *)"";
    }
  } else if (rec->type) {
    if (rec->type_code == 5 || rec->type_code == 12 || rec->type_code == 2 ||
        rec->type_code == 39 || rec->type_code == 23 || 
        (rec->type_code >= 3 && rec->type_code <= 4) || 
        (rec->type_code >= 7 && rec->type_code <= 9) ||
        rec->type_code == 30 /* NXT: rdata[0] = Next Domain Name */) {
      if (rec->rdata_count > 0)
        rec->rdata[0] = expand_domain_name(rec->rdata[0], *origin_io, arena);
    } else if (rec->type_code == 38) { // A6 (RFC 2874): prefix name は rdata[2]
      // prefix_len (rdata[0]) > 0 のときのみ rdata[2] にプレフィックス名が存在する
      if (rec->rdata_count >= 3) {
        uint8_t a6_plen = (uint8_t)atoi(rec->rdata[0]);
        if (a6_plen > 0)
          rec->rdata[2] = expand_domain_name(rec->rdata[2], *origin_io, arena);
      }
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
      uint8_t gw_type;
      if (rec->rdata_count > 3 && parse_u8(rec->rdata[1], &gw_type) && gw_type == 3) {
        rec->rdata[3] = expand_domain_name(rec->rdata[3], *origin_io, arena);
      }
    } else if (rec->type_code == 260) { // AMTRELAY
      uint8_t gw_type;
      if (rec->rdata_count > 3 && parse_u8(rec->rdata[2], &gw_type) && gw_type == 3) {
        rec->rdata[3] = expand_domain_name(rec->rdata[3], *origin_io, arena);
      }
    } else if (rec->type_code == 55) { // HIP
      // Base64トークンをドメイン名展開から除外し、Rendezvous Serverのみ展開する
      bool in_pubkey = true;
      for (int i = 2; i < rec->rdata_count; i++) {
        // ドットを含む場合はドメイン名 (Rendezvous Server) と判定
        if (strchr(rec->rdata[i], '.') != NULL) {
          in_pubkey = false;
        }
        if (!in_pubkey) {
          rec->rdata[i] = expand_domain_name(rec->rdata[i], *origin_io, arena);
        } else {
          // Base64の末尾パディング '=' に達した後のトークンはRendezvous Server
          size_t tlen = strlen(rec->rdata[i]);
          if (tlen > 0 && rec->rdata[i][tlen - 1] == '=') {
            in_pubkey = false;
          }
        }
      }
    } else if (rec->type_code == 64 || rec->type_code == 65) { // SVCB / HTTPS
      if (rec->rdata_count > 1) {
        if (strcmp(rec->rdata[1], ".") != 0) {
          rec->rdata[1] = expand_domain_name(rec->rdata[1], *origin_io, arena);
        }
      }
    } else if (rec->type_code == 58) { // TALINK: prev + next
      if (rec->rdata_count > 0)
        rec->rdata[0] = expand_domain_name(rec->rdata[0], *origin_io, arena);
      if (rec->rdata_count > 1)
        rec->rdata[1] = expand_domain_name(rec->rdata[1], *origin_io, arena);
    }

    // Validate domain name length in RDATA
    for (int j = 0; j < rec->rdata_count; j++) {
      bool is_domain_field = false;
      switch (rec->type_code) {
        case 2: case 5: case 12: case 39: case 23: case 3: case 4: case 7: case 8: case 9:
          if (j == 0) is_domain_field = true;
          break;
        case 15: case 18: case 36: case 21: case 107:
          if (j == 1) is_domain_field = true;
          break;
        case 6: case 14: case 17:
          if (j == 0 || j == 1) is_domain_field = true;
          break;
        case 33:
          if (j == 3) is_domain_field = true;
          break;
        case 35:
          if (j == 5) is_domain_field = true;
          break;
        case 26:
          if (j == 1 || j == 2) is_domain_field = true;
          break;
        case 45: case 260:
          if (j == 3) is_domain_field = true;
          break;
        case 30: // NXT (RFC 2535): rdata[0] = Next Domain Name
          if (j == 0) is_domain_field = true;
          break;
        case 38: // A6 (RFC 2874): rdata[2] = prefix name (prefix_len > 0)
          if (j == 2) is_domain_field = true;
          break;
        case 58: // TALINK
          if (j == 0 || j == 1) is_domain_field = true;
          break;
        default:
          if ((rec->type_code == 64 || rec->type_code == 65) && j == 1 && strcmp(rec->rdata[1], ".") != 0) {
            is_domain_field = true;
          }
          break;
      }
      if (is_domain_field && rec->rdata[j]) {
        if (!validate_domain_name_length(rec->rdata[j], ctx ? ctx->err_out : NULL, rec->rdata[j], buf)) {
          return -1;
        }
      }
    }

    if (rec->type_code == 22) { // NSAP
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
    } else if (rec->type_code == 1) { // A
        if (rec->rdata_count != 1) {
            if (ctx && ctx->err_out) {
                ctx->err_out->error_message = "A record requires exactly 1 parameter";
                ctx->err_out->error_offset = rec->type - buf;
                ctx->err_out->token_length = strlen(rec->type);
            }
            return -1;
        }
        struct in_addr tmp;
        if (inet_pton(AF_INET, rec->rdata[0], &tmp) != 1) {
            if (ctx && ctx->err_out) {
                ctx->err_out->error_message = "invalid IPv4 address literal in A record";
                ctx->err_out->error_offset = rec->type - buf;
                ctx->err_out->token_length = strlen(rec->type);
            }
            return -1;
        }
    } else if (rec->type_code == 28) { // AAAA
        if (rec->rdata_count != 1) {
            if (ctx && ctx->err_out) {
                ctx->err_out->error_message = "AAAA record requires exactly 1 parameter";
                ctx->err_out->error_offset = rec->type - buf;
                ctx->err_out->token_length = strlen(rec->type);
            }
            return -1;
        }
        struct in6_addr tmp;
        if (inet_pton(AF_INET6, rec->rdata[0], &tmp) != 1) {
            if (ctx && ctx->err_out) {
                ctx->err_out->error_message = "invalid IPv6 address literal in AAAA record";
                ctx->err_out->error_offset = rec->type - buf;
                ctx->err_out->token_length = strlen(rec->type);
            }
            return -1;
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
  if (finalize) {
    for (size_t i = 0; i < arena->count; i++) {
      dns_record_preparse_cache(arena, &arena->records[i]);
    }
  }
  return arena->count;
}

void zone_arena_init(zone_arena_t *arena) {
  if (!arena) return;
  memset(arena, 0, sizeof(*arena));
}
void zone_arena_free_include_buffers(zone_arena_t *arena) {
  for (int i = 0; i < arena->file_buf_count; i++) {
    free(arena->file_bufs[i]);
    free(arena->display_bufs[i]);
    free(arena->file_paths[i]);
  }
  arena->file_buf_count = 0;
}

void free_ecs_tags_array(ecs_tag_def_t *tags, int count) {
  if (!tags) return;
  for (int i = 0; i < count; i++) {
    if (tags[i].tag) free(tags[i].tag);
    if (tags[i].cidrs) {
      for (int j = 0; j < tags[i].cidr_count; j++) {
        if (tags[i].cidrs[j].cidr) free(tags[i].cidrs[j].cidr);
      }
      free(tags[i].cidrs);
    }
  }
  free(tags);
}

ecs_tag_def_t *clone_ecs_tags_array(const ecs_tag_def_t *src, int count) {
  if (!src || count <= 0) return NULL;
  ecs_tag_def_t *dst = calloc(count, sizeof(ecs_tag_def_t));
  if (!dst) return NULL;
  for (int i = 0; i < count; i++) {
    dst[i].tag = src[i].tag ? strdup(src[i].tag) : NULL;
    dst[i].cidr_count = src[i].cidr_count;
    if (src[i].cidr_count > 0 && src[i].cidrs) {
      dst[i].cidrs = calloc(src[i].cidr_count, sizeof(ecs_cidr_entry_t));
      if (dst[i].cidrs) {
        for (int j = 0; j < src[i].cidr_count; j++) {
          dst[i].cidrs[j].cidr = src[i].cidrs[j].cidr ? strdup(src[i].cidrs[j].cidr) : NULL;
          dst[i].cidrs[j].parsed = src[i].cidrs[j].parsed;
        }
      }
    }
  }
  return dst;
}

void free_zone_response_cache(zone_arena_t *arena) {
  if (!arena) return;
  if (arena->response_cache.buckets) {
    free(arena->response_cache.buckets);
    arena->response_cache.buckets = NULL;
    arena->response_cache.bucket_count = 0;
    arena->response_cache.entry_count = 0;
  }
}

void zone_arena_destroy(zone_arena_t *arena) {
  free(arena->records);
  for (int i = 0; i < arena->data_pool_count; i++)
    free(arena->data_pools[i]);
  free(arena->hash_table);
  zone_arena_free_sorted_indexes(arena);
  free(arena->locations);
  arena->locations = NULL;
  arena->location_count = 0;
  free_ecs_tags_array(arena->bind_location_tags, arena->bind_location_tag_count);
  arena->bind_location_tags = NULL;
  arena->bind_location_tag_count = 0;
  free_ecs_tags_array(arena->bind_ecs_tags, arena->bind_ecs_tag_count);
  arena->bind_ecs_tags = NULL;
  arena->bind_ecs_tag_count = 0;
  if (arena->bind_ecs_trusted_resolvers) {
    for (int i = 0; i < arena->bind_ecs_trusted_resolver_count; i++) {
      free(arena->bind_ecs_trusted_resolvers[i]);
    }
    free(arena->bind_ecs_trusted_resolvers);
    arena->bind_ecs_trusted_resolvers = NULL;
    arena->bind_ecs_trusted_resolver_count = 0;
  }
  if (arena->bind_ecs_trusted_resolvers_parsed) {
    free(arena->bind_ecs_trusted_resolvers_parsed);
    arena->bind_ecs_trusted_resolvers_parsed = NULL;
  }
  arena->prelinked_glue = NULL;
  arena->prelinked_glue_count = 0;
  free_zone_response_cache(arena);
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
uint32_t calc_fnv1a_strn(const char *str, size_t len) {
  uint32_t hash = 2166136261u;
  for (size_t i = 0; i < len; i++) {
    uint8_t c = (uint8_t)str[i];
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
static int cmp_canonical_nsec_ptr(const void *a, const void *b) {
  const dns_record_t *r1 = *(const dns_record_t **)a;
  const dns_record_t *r2 = *(const dns_record_t **)b;
  return compare_canonical_name(r1->name, r2->name);
}

static int cmp_canonical_name_ptr(const void *a, const void *b) {
  const char *s1 = *(const char * const *)a;
  const char *s2 = *(const char * const *)b;
  return compare_canonical_name(s1, s2);
}

void zone_arena_free_sorted_indexes(zone_arena_t *arena) {
  free(arena->nsec_records);
  arena->nsec_records = NULL;
  arena->nsec_count = 0;
  free(arena->nsec3_chains);
  arena->nsec3_chains = NULL;
  arena->nsec3_chain_count = 0;
  free(arena->nsec3_entries);
  arena->nsec3_entries = NULL;
  memset(&arena->nsec3_active, 0, sizeof(arena->nsec3_active));
  free(arena->sorted_unique_names);
  arena->sorted_unique_names = NULL;
  arena->sorted_unique_count = 0;
}

bool nsec3_rdata_params(const dns_record_t *rec, uint8_t *algorithm, uint16_t *iterations, const char **salt) {
  if (!rec || rec->rdata_count < 4 || !rec->rdata[3] ||
      !parse_u8(rec->rdata[0], algorithm) || !parse_u16(rec->rdata[2], iterations))
    return false;
  *salt = rec->rdata[3];
  return true;
}

/* RFC 5155 §3.3: the salt field is "-" when the salt is empty; hex digits compare case-insensitively. */
static int cmp_nsec3_salt(const char *a, const char *b) {
  if (strcmp(a, "-") == 0) a = "";
  if (strcmp(b, "-") == 0) b = "";
  return strcasecmp(a, b);
}

static int cmp_nsec3_params(uint8_t a_alg, uint16_t a_it, const char *a_salt,
                            uint8_t b_alg, uint16_t b_it, const char *b_salt) {
  if (a_alg != b_alg) return a_alg < b_alg ? -1 : 1;
  if (a_it != b_it) return a_it < b_it ? -1 : 1;
  return cmp_nsec3_salt(a_salt, b_salt);
}

static int cmp_nsec3_hash(const char *a, size_t a_len, const char *b, size_t b_len) {
  int c = strncasecmp(a, b, a_len < b_len ? a_len : b_len);
  if (c != 0) return c;
  return a_len < b_len ? -1 : (a_len > b_len ? 1 : 0);
}

static int cmp_nsec3_entry_params(const nsec3_index_entry_t *x, const nsec3_index_entry_t *y) {
  return cmp_nsec3_params(x->algorithm, x->iterations, x->salt, y->algorithm, y->iterations, y->salt);
}

static int cmp_nsec3_entry(const void *a, const void *b) {
  const nsec3_index_entry_t *x = a, *y = b;
  int c = cmp_nsec3_entry_params(x, y);
  return c != 0 ? c : cmp_nsec3_hash(x->hash, x->hash_len, y->hash, y->hash_len);
}

/* Fills `e` for an NSEC3 RR that can be indexed: all five fixed RDATA fields, and an owner whose first label is
 * base32hex digits only (RFC 4648 §7, at most 63 octets) followed by the zone name. */
static bool nsec3_index_entry_init(dns_record_t *rec, nsec3_index_entry_t *e) {
  if (!rec->name || rec->type_code != 50 || rec->rdata_count < 5 || !rec->rdata[4] ||
      !nsec3_rdata_params(rec, &e->algorithm, &e->iterations, &e->salt))
    return false;
  const char *dot = strchr(rec->name, '.');
  if (!dot || dot == rec->name || dot[1] == '\0' || dot - rec->name > 63) return false;
  for (const char *p = rec->name; p < dot; p++) {
    char c = (char)toupper((unsigned char)*p);
    if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'V'))) return false;
  }
  e->hash = rec->name;
  e->hash_len = (uint8_t)(dot - rec->name);
  e->rec = rec;
  return true;
}

/* RFC 5155 §7.2: the covering and matching NSEC3 RRs of an answer come from one chain. Group the NSEC3 RRs by
 * (algorithm, iterations, salt) and sort each group in hash order for binary search (R-34). Returns -1 on OOM. */
static int build_nsec3_index(zone_arena_t *arena) {
  size_t n = 0;
  nsec3_index_entry_t tmp;
  for (size_t i = 0; i < arena->count; i++)
    if (nsec3_index_entry_init(&arena->records[i], &tmp)) n++;
  if (n == 0) return 0;

  nsec3_index_entry_t *entries = malloc(sizeof(*entries) * n);
  if (!entries) return -1;
  size_t k = 0;
  for (size_t i = 0; i < arena->count && k < n; i++)
    if (nsec3_index_entry_init(&arena->records[i], &entries[k])) k++;
  qsort(entries, k, sizeof(*entries), cmp_nsec3_entry);

  size_t chains = 0;
  for (size_t i = 0; i < k; i++)
    if (i == 0 || cmp_nsec3_entry_params(&entries[i - 1], &entries[i]) != 0) chains++;
  nsec3_chain_t *chain = calloc(chains, sizeof(*chain));
  if (!chain) {
    free(entries);
    return -1;
  }
  size_t c = 0;
  for (size_t i = 0; i < k; i++) {
    if (i == 0 || cmp_nsec3_entry_params(&entries[i - 1], &entries[i]) != 0) {
      nsec3_chain_t *ch = &chain[c++];
      ch->algorithm = entries[i].algorithm;
      ch->iterations = entries[i].iterations;
      ch->salt = entries[i].salt;
      ch->entries = &entries[i];
    }
    chain[c - 1].count++;
  }
  arena->nsec3_entries = entries;
  arena->nsec3_chains = chain;
  arena->nsec3_chain_count = chains;
  return 0;
}

const nsec3_chain_t *zone_find_nsec3_chain(const zone_arena_t *arena, const dns_record_t *param) {
  uint8_t alg;
  uint16_t it;
  const char *salt;
  if (!arena || !nsec3_rdata_params(param, &alg, &it, &salt)) return NULL;
  for (size_t i = 0; i < arena->nsec3_chain_count; i++) {
    const nsec3_chain_t *ch = &arena->nsec3_chains[i];
    if (cmp_nsec3_params(ch->algorithm, ch->iterations, ch->salt, alg, it, salt) == 0) return ch;
  }
  return NULL;
}

size_t hex_to_bytes(const char *hex, uint8_t *out, size_t max_out) {
  if (!hex || strcmp(hex, "-") == 0) return 0;
  size_t hlen = strlen(hex);
  if (hlen % 2 != 0 || hlen / 2 > max_out) return (size_t)-1;
  for (size_t i = 0; i < hlen; i += 2) {
    int hi = hex_char_to_val(hex[i]), lo = hex_char_to_val(hex[i + 1]);
    if (hi < 0 || lo < 0) return (size_t)-1;
    out[i / 2] = (uint8_t)((hi << 4) | lo);
  }
  return hlen / 2;
}

/* RFC 5155 §3.1.7: every Next Hashed Owner Name is the owner hash of the following RR in hash order, and the last RR
 * points back to the first, so a complete chain covers every possible hash. */
static bool nsec3_chain_complete(const nsec3_chain_t *ch) {
  for (size_t i = 0; i < ch->count; i++) {
    const nsec3_index_entry_t *next = &ch->entries[(i + 1) % ch->count];
    const char *nh = ch->entries[i].rec->rdata[4];
    if (strlen(nh) != next->hash_len || strncasecmp(nh, next->hash, next->hash_len) != 0) return false;
  }
  return ch->count > 0;
}

/* R-31: choose the NSEC3 parameters of the zone once, when the index is built (not per query). The apex is the owner
 * of the SOA. Usable NSEC3PARAM RRs at the apex: Flags 0 (RFC 5155 §4.1.2 "NSEC3PARAM RRs with a Flags field value
 * other than zero MUST be ignored"), hash algorithm 1 (SHA-1, the only one defined, §11; §7.4 for unknown ones), and
 * a salt of 0-255 octets in hex (§3.1.5, §3.2). With several of them the server "must choose one" (§7.3): the first
 * in record order whose chain is complete, else the first whose chain is indexed, else the first usable one. */
static void select_nsec3_params(zone_arena_t *arena) {
  const char *apex = NULL;
  for (size_t i = 0; i < arena->count && !apex; i++)
    if (arena->records[i].name && arena->records[i].type_code == 6) apex = arena->records[i].name;
  if (!apex) return;

  size_t seen = 0, usable = 0;
  int best_rank = 0; // 3 = complete chain, 2 = indexed chain, 1 = usable without NSEC3 RRs
  for (size_t i = 0; i < arena->count; i++) {
    const dns_record_t *rec = &arena->records[i];
    if (rec->type_code != 51 || !rec->name || !domain_names_match_ci(rec->name, apex)) continue;
    seen++;
    uint8_t alg, flags;
    uint16_t it;
    const char *salt_text;
    nsec3_params_t p;
    memset(&p, 0, sizeof(p));
    if (!nsec3_rdata_params(rec, &alg, &it, &salt_text) || !parse_u8(rec->rdata[1], &flags) || flags != 0 ||
        alg != 1)
      continue;
    size_t salt_len = hex_to_bytes(salt_text, p.salt, sizeof(p.salt));
    if (salt_len == (size_t)-1) continue;
    usable++;
    p.param = rec;
    p.chain = zone_find_nsec3_chain(arena, rec);
    p.algorithm = alg;
    p.iterations = it;
    p.salt_len = (uint8_t)salt_len;
    int rank = !p.chain ? 1 : (nsec3_chain_complete(p.chain) ? 3 : 2);
    if (rank > best_rank) {
      best_rank = rank;
      arena->nsec3_active = p;
    }
  }
  if (seen == 0) return;
  const nsec3_params_t *a = &arena->nsec3_active;
  if (!a->param) {
    syslog(LOG_NOTICE, "[Zone] %s: none of the %zu NSEC3PARAM RRs is usable (Flags 0, algorithm 1, salt of at most "
           "255 octets; RFC 5155 s4.1.2); NSEC3 is not used for denial of existence", apex, seen);
  } else if (usable > 1 || best_rank < 3) {
    syslog(LOG_NOTICE, "[Zone] %s: using NSEC3PARAM 1 0 %u %s (%zu usable of %zu; chain %s)", apex, a->iterations,
           a->param->rdata[3], usable, seen,
           best_rank == 3 ? "complete" : (best_rank == 2 ? "INCOMPLETE" : "MISSING"));
  }
}

/* [T9] RFC 2181 s5.2: same owner+type RRset TTLs normalized to minimum.
 * RFC 4035 s2.2: RRSIG TTL aligned to the covered RRset (post phase-1) TTL. */
static void harmonize_rrset_ttls(zone_arena_t *arena) {
  if (!arena->hash_table || arena->hash_size == 0 || arena->count == 0) return;

  bool *processed = calloc(arena->count, sizeof(bool));
  if (!processed) return; /* OOM: skip normalization safely */

  /* Phase 1: Non-RRSIG records - group by owner+type, normalize to min TTL */
  for (size_t i = 0; i < arena->count; i++) {
    if (processed[i]) continue;
    dns_record_t *ri = &arena->records[i];
    if (!ri->name || ri->type_code == 46) continue;

    uint32_t hash = calc_fnv1a_str(ri->name);
    size_t idx = hash & (arena->hash_size - 1);

    uint32_t min_ttl = ri->ttl_value;
    for (int j = arena->hash_table[idx]; j != -1; j = arena->records[j].next_record) {
      if ((size_t)j == i) continue;
      dns_record_t *rj = &arena->records[j];
      if (rj->type_code != ri->type_code || !rj->name) continue;
      if (strcasecmp(rj->name, ri->name) != 0) continue;
      if (rj->ttl_value < min_ttl) min_ttl = rj->ttl_value;
    }

    if (ri->ttl_value != min_ttl) {
      syslog(LOG_WARNING, "[Zone] RRset '%s' type %u: inconsistent TTLs normalized to %u (RFC 2181 s5.2)",
             ri->name, ri->type_code, min_ttl);
    }
    ri->ttl_value = min_ttl;
    processed[i] = true;

    for (int j = arena->hash_table[idx]; j != -1; j = arena->records[j].next_record) {
      if ((size_t)j == i || processed[j]) continue;
      dns_record_t *rj = &arena->records[j];
      if (rj->type_code != ri->type_code || !rj->name) continue;
      if (strcasecmp(rj->name, ri->name) != 0) continue;
      rj->ttl_value = min_ttl;
      processed[j] = true;
    }
  }

  /* Phase 2: RRSIG records - align TTL to the covered RRset's (normalized) TTL */
  for (size_t i = 0; i < arena->count; i++) {
    dns_record_t *ri = &arena->records[i];
    if (!ri->name || ri->type_code != 46) continue;

    uint16_t covered = 0;
    if (ri->is_cached) {
      covered = ri->cache.rrsig.type_covered;
    } else if (ri->rdata_count >= 1 && ri->rdata[0]) {
      covered = (uint16_t)get_type_code(ri->rdata[0]);
    }
    if (covered == 0) continue; /* unknown covered type: skip */

    uint32_t hash = calc_fnv1a_str(ri->name);
    size_t idx = hash & (arena->hash_size - 1);
    for (int j = arena->hash_table[idx]; j != -1; j = arena->records[j].next_record) {
      dns_record_t *rj = &arena->records[j];
      if (rj->type_code != covered || !rj->name) continue;
      if (strcasecmp(rj->name, ri->name) != 0) continue;
      if (ri->ttl_value != rj->ttl_value) {
        syslog(LOG_WARNING, "[Zone] RRSIG covering type %u at '%s': TTL %u adjusted to %u (RFC 4035 s2.2)",
               covered, ri->name, ri->ttl_value, rj->ttl_value);
      }
      ri->ttl_value = rj->ttl_value;
      break;
    }
  }

  free(processed);

  /* Sync the string ttl field to ttl_value for tools that re-export zone text */
  for (size_t i = 0; i < arena->count; i++) {
    dns_record_t *rec = &arena->records[i];
    if (!rec->name) continue;
    char buf[16];
    snprintf(buf, sizeof(buf), "%u", rec->ttl_value);
    char *new_ttl = arena_strdup(arena, buf);
    if (new_ttl) rec->ttl = new_ttl;
  }
}

int build_zone_index(zone_arena_t *arena, bool harmonize_ttls) {
  assert(calc_fnv1a_str("*.") == FNV1A_WILDCARD_PREFIX_HASH);
  if (arena->hash_table) {
    free(arena->hash_table);
    arena->hash_table = NULL;
  }
  zone_arena_free_sorted_indexes(arena);
  arena->hash_size = next_pow2(arena->count * 2);
  if (arena->hash_size == 0) arena->hash_size = 1;
  arena->hash_table = malloc(sizeof(int) * arena->hash_size);
  if (!arena->hash_table) {
    syslog(LOG_ERR, "[Zone] build_zone_index: OOM during hash_table allocation");
    return -1;
  }
  for (size_t i = 0; i < arena->hash_size; i++)
    arena->hash_table[i] = -1;

  size_t nsec_cnt = 0;
  for (size_t i = arena->count; i-- > 0; ) {
    dns_record_t *rec = &arena->records[i];
    if (!rec->name)
      continue;
    uint32_t hash = calc_fnv1a_str(rec->name);
    size_t idx = hash & (arena->hash_size - 1);
    rec->next_record = arena->hash_table[idx];
    arena->hash_table[idx] = i;
    if (rec->type_code == 47 && rec->rdata_count >= 1 && rec->rdata[0]) {
      nsec_cnt++;
    }
  }

  if (harmonize_ttls) {
    harmonize_rrset_ttls(arena);
  }

  if (nsec_cnt > 0) {
    arena->nsec_records = malloc(sizeof(dns_record_t *) * nsec_cnt);
    if (arena->nsec_records) {
      size_t idx = 0;
      for (size_t i = 0; i < arena->count; i++) {
        dns_record_t *rec = &arena->records[i];
        if (rec->name && rec->type_code == 47 && rec->rdata_count >= 1 && rec->rdata[0]) {
          arena->nsec_records[idx++] = rec;
        }
      }
      arena->nsec_count = idx;
      qsort(arena->nsec_records, arena->nsec_count, sizeof(dns_record_t *), cmp_canonical_nsec_ptr);
    } else {
      /* X-22: without the index every NSEC lookup would scan the whole zone (the random-subdomain cost of R-34);
       * fail like the NSEC3 index instead (the callers treat it as a load / transfer / UPDATE failure). */
      syslog(LOG_ERR, "[Zone] build_zone_index: OOM during NSEC index allocation");
      return -1;
    }
  }

  if (build_nsec3_index(arena) != 0) {
    syslog(LOG_ERR, "[Zone] build_zone_index: OOM during NSEC3 index allocation");
    return -1;
  }
  select_nsec3_params(arena);

  if (arena->count > 0) {
    char **tmp_names = malloc(sizeof(char *) * arena->count);
    if (tmp_names) {
      size_t valid_cnt = 0;
      for (size_t i = 0; i < arena->count; i++) {
        if (arena->records[i].name) {
          tmp_names[valid_cnt++] = arena->records[i].name;
        }
      }
      if (valid_cnt > 0) {
        qsort(tmp_names, valid_cnt, sizeof(char *), cmp_canonical_name_ptr);
        size_t ucnt = 0;
        for (size_t i = 0; i < valid_cnt; i++) {
          if (i == 0 || compare_canonical_name(tmp_names[i], tmp_names[ucnt - 1]) != 0) {
            tmp_names[ucnt++] = tmp_names[i];
          }
        }
        arena->sorted_unique_names = tmp_names;
        arena->sorted_unique_count = ucnt;
      } else {
        free(tmp_names);
        arena->sorted_unique_names = NULL;
        arena->sorted_unique_count = 0;
      }
    } else {
      arena->sorted_unique_names = NULL;
      arena->sorted_unique_count = 0;
    }
  }

  return 0;
}

int validate_zone_dname(zone_arena_t *arena, parse_error_t *err) {
  if (!arena || !arena->hash_table) return 0;
  for (size_t i = 0; i < arena->count; i++) {
    dns_record_t *rec = &arena->records[i];
    if (!rec->name) continue;
    const char *parent = rec->name;
    while ((parent = strchr_unescaped(parent, '.')) != NULL) {
      parent++;
      if (*parent == '\0') break;
      uint32_t p_hash = calc_fnv1a_str(parent);
      size_t p_idx = p_hash & (arena->hash_size - 1);
      for (int j = arena->hash_table[p_idx]; j != -1; j = arena->records[j].next_record) {
        if (arena->records[j].type_code == 39 && strcasecmp(arena->records[j].name, parent) == 0) {
          if (err) {
            err->error_message = "Record exists under a DNAME (RFC 6672 violation)";
            // Approximate offset/length for error reporting if possible, else 0
            err->error_offset = 0;
            err->token_length = 0;
            err->file_path = NULL;
          }
          return -1;
        }
      }
    }
  }
  return 0;
}

int validate_zone_name_lengths(zone_arena_t *arena, parse_error_t *err) {
  if (!arena || !arena->hash_table) return 0;
  for (size_t i = 0; i < arena->count; i++) {
    dns_record_t *rec = &arena->records[i];
    
    // Check owner name
    if (rec->name && strlen(rec->name) > 1024) {
        if (err) {
            err->error_message = "Owner name exceeds maximum supported length (1024 bytes)";
            err->error_offset = 0;
            err->token_length = 0;
            err->file_path = NULL;
        }
        return -1;
    }
    
    // Check RDATA domain names based on type
    for (int j = 0; j < rec->rdata_count; j++) {
        bool is_domain_name = false;
        switch (rec->type_code) {
            case 2: case 3: case 4: case 5: case 7: case 8: case 9: case 12: case 23: case 39: // NS, MD, MF, CNAME, MB, MG, MR, PTR, NSAP-PTR, DNAME
                if (j == 0) is_domain_name = true;
                break;
            case 15: // MX
                if (j == 1) is_domain_name = true;
                break;
            case 6: // SOA
                if (j == 0 || j == 1) is_domain_name = true;
                break;
            case 33: // SRV
                if (j == 3) is_domain_name = true;
                break;
            case 35: // NAPTR
                if (j == 5) is_domain_name = true;
                break;
            case 14: case 17: // MINFO, RP
                if (j == 0 || j == 1) is_domain_name = true;
                break;
            case 18: case 36: case 21: case 107: // AFSDB, KX, RT, LP
                if (j == 1) is_domain_name = true;
                break;
            case 26: // PX
                if (j == 1 || j == 2) is_domain_name = true;
                break;
            case 30: // NXT (RFC 2535): rdata[0] = Next Domain Name
                if (j == 0) is_domain_name = true;
                break;
            case 38: // A6 (RFC 2874): rdata[2] = prefix name
                if (j == 2) is_domain_name = true;
                break;
            case 58: // TALINK: rdata[0]=prev, rdata[1]=next
                if (j == 0 || j == 1) is_domain_name = true;
                break;
            default:
                break;
        }
        if (is_domain_name && rec->rdata[j] && strlen(rec->rdata[j]) > 1024) {
            if (err) {
                err->error_message = "RDATA domain name exceeds maximum supported length (1024 bytes)";
                err->error_offset = 0;
                err->token_length = 0;
                err->file_path = NULL;
            }
            return -1;
        }
    }
  }
  return 0;
}


/* ゾーン外のレコード (オーナーが apex でもその下でもない) を取り除く。
 * RFC 1034 §4.2: ゾーンは apex とその下のデータからなる。RFC 5936 §2.2: AXFR は
 * そのゾーンを転送する。ゾーン外のデータを読み込むと AXFR で送られ、セカンダリが
 * 受け取れない (R-27)。BIND と同様に警告して無視する。
 * build_zone_index() より前 (レコードの添字を指すものが無い間) に呼ぶこと。
 * report が NULL でなければ、取り除くレコードごとに呼ぶ。戻り値は取り除いた件数。 */
size_t zone_arena_drop_out_of_zone(zone_arena_t *arena, const char *apex,
                                   void (*report)(const dns_record_t *rec, void *ud), void *ud) {
  if (!arena || !apex || !arena->records) return 0;
  size_t kept = 0, dropped = 0;
  for (size_t i = 0; i < arena->count; i++) {
    dns_record_t *r = &arena->records[i];
    if (r->name && !domain_name_is_at_or_below(r->name, apex)) {
      if (report) report(r, ud);
      dropped++;
      continue;
    }
    if (kept != i) arena->records[kept] = *r;
    kept++;
  }
  arena->count = kept;
  return dropped;
}

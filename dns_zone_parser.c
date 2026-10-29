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
#include <errno.h>
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
#include "dns_log.h"
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
    if (arena->data_pool_count >= ZONE_ARENA_MAX_POOLS)
      return NULL;
    if (arena->data_pool_count >= arena->data_pool_cap) {
      int cap = arena->data_pool_cap ? arena->data_pool_cap * 2 : 4;
      if (cap > ZONE_ARENA_MAX_POOLS) cap = ZONE_ARENA_MAX_POOLS;
      char **pools = realloc(arena->data_pools, (size_t)cap * sizeof(*pools));
      if (!pools) return NULL;
      arena->data_pools = pools;
      arena->data_pool_cap = cap;
    }
    if (arena->data_pool_count == 0)
      arena->current_pool_cap = arena->first_pool_cap ? arena->first_pool_cap : 64 * 1024;
    else if (arena->first_pool_cap && arena->data_pool_count < 4)
      /* S4: 最初のプールを見積もったときは、少し足りなかった分を半分の大きさで足す (倍にすると
       * 小さいゾーンの多くで半分が空く)。見積もりが大きく外れたら倍に戻る */
      arena->current_pool_cap = arena->first_pool_cap / 2 > 1024 ? arena->first_pool_cap / 2 : 1024;
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
  /* 同じ表現で同じ値なら等しい (よくある場合はここで終わる) */
  bool same_text = (a->rdata_count == b->rdata_count && a->generic_len == b->generic_len);
  for (int i = 0; same_text && i < a->rdata_count; i++) {
    if ((a->rdata[i] == NULL) != (b->rdata[i] == NULL)) same_text = false;
    else if (a->rdata[i] && b->rdata[i] && strcmp(a->rdata[i], b->rdata[i]) != 0) same_text = false;
  }
  if (same_text && a->generic_len > 0 && memcmp(a->generic_data, b->generic_data, a->generic_len) != 0) same_text = false;
  if (same_text) return true;
  /* X-16, X-25: RFC 2136 §1.1.1 (RR は RDATA が等しければ等しい)、§1.1.2 (名前は RFC 1035 §2.3.3 のとおり
   * 大文字小文字を区別しない)。テキスト (ゾーンファイル) とワイヤ (転送、UPDATE) の表現の違い、数値の書き方、
   * 名前の大文字小文字に依らないよう、RFC 4034 §6.2 の正規形の RDATA で比べる (BIND の dns_rdata_compare()
   * と同じく、一覧に無い型の名前は区別する)。 */
  uint8_t wa[65535], wb[65535];
  long la = dns_record_canonical_rdata(a, wa, sizeof(wa));
  if (la < 0) return false;
  long lb = dns_record_canonical_rdata(b, wb, sizeof(wb));
  return lb == la && memcmp(wa, wb, (size_t)la) == 0;
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

/* Lexical normalization of a path into out: "." and empty components and "x/.." pairs are removed.  An absolute path whose ".." would
 * climb above "/" is refused (false).  A relative path keeps the ".." it cannot collapse; an empty relative result is ".".  No
 * symbolic link is looked at: the $INCLUDE ranges are decided on the text (the loader opens the last component with O_NOFOLLOW). */
#define INCLUDE_PATH_COMPONENTS_MAX 256
static bool include_path_normalize(const char *in, char *out, size_t cap) {
    const char *comp[INCLUDE_PATH_COMPONENTS_MAX];
    size_t clen[INCLUDE_PATH_COMPONENTS_MAX];
    size_t n = 0;
    bool is_abs = in[0] == '/';
    const char *p = in;
    while (*p) {
        while (*p == '/') p++;
        if (!*p) break;
        const char *e = p;
        while (*e && *e != '/') e++;
        size_t cl = (size_t)(e - p);
        if (cl == 1 && p[0] == '.') {
            /* nothing */
        } else if (cl == 2 && p[0] == '.' && p[1] == '.') {
            if (n > 0 && !(clen[n - 1] == 2 && comp[n - 1][0] == '.' && comp[n - 1][1] == '.')) {
                n--;
            } else if (is_abs) {
                return false;
            } else {
                if (n >= INCLUDE_PATH_COMPONENTS_MAX) return false;
                comp[n] = p; clen[n++] = cl;
            }
        } else {
            if (n >= INCLUDE_PATH_COMPONENTS_MAX) return false;
            comp[n] = p; clen[n++] = cl;
        }
        p = e;
    }
    size_t o = 0;
    if (is_abs) {
        if (cap < 2) return false;
        out[o++] = '/';
    }
    for (size_t i = 0; i < n; i++) {
        if (o + clen[i] + 2 > cap) return false;
        if (i > 0) out[o++] = '/';
        memcpy(out + o, comp[i], clen[i]);
        o += clen[i];
    }
    if (o == 0) {
        if (cap < 2) return false;
        out[o++] = '.';
    }
    out[o] = '\0';
    return true;
}

/* Is the normalized path inside the tree of the normalized directory root (or equal to it)?  Both absolute, or both relative. */
static bool include_path_within(const char *path, const char *root) {
    bool pabs = path[0] == '/', rabs = root[0] == '/';
    if (pabs != rabs) return false;
    if (strcmp(root, ".") == 0)        /* the working directory: any relative path that does not climb out of it */
        return !(path[0] == '.' && path[1] == '.' && (path[2] == '\0' || path[2] == '/'));
    size_t rl = strlen(root);
    /* "/" as a root is only the files directly in it: the server cannot open directories below "/" (dir_fd_cache_add_root() does not
     * make "/" a root), so a zone file in "/" does not make the whole file system an $INCLUDE range */
    if (strcmp(root, "/") == 0) return strchr(path + 1, '/') == NULL;
    return strncmp(path, root, rl) == 0 && (path[rl] == '\0' || path[rl] == '/');
}

/* The file an $INCLUDE names, or NULL with the reason in ctx->err_out.
 * BIND 9.20 ARM 3.5.5.3: "The filename can be an absolute path, or a relative path"; a relative one is read from named's working directory,
 * which is options { directory } (ctx->directory); without it the directory of the zone file (ctx->base_dir) is used, as always.
 * The Backend runs in capability mode and can open files only below directories that were opened at startup: the directory of the zone
 * file and options { directory }.  An absolute path, or one that leaves the base through "..", is accepted only if the normalized path
 * stays inside one of those two trees; the same rule applies in karicheck so that it gives the same verdict as the server. */
static char *resolve_include_path(const parse_context_t *ctx, const char *path) {
    parse_error_t *err = ctx->err_out;
    if (path[0] == '\0') {
        if (err) err->error_message = "$INCLUDE requires a filename";
        return NULL;
    }
    char raw[PATH_MAX], norm[PATH_MAX], root1[PATH_MAX], root2[PATH_MAX];
    bool inside = false;
    const char *base = ctx->directory && ctx->directory[0] ? ctx->directory : ctx->base_dir;
    if (path[0] == '/') {
        if (snprintf(raw, sizeof(raw), "%s", path) >= (int)sizeof(raw)) goto too_long;
    } else {
        if (snprintf(raw, sizeof(raw), "%s/%s", base, path) >= (int)sizeof(raw)) goto too_long;
    }
    if (include_path_normalize(raw, norm, sizeof(norm))) {
        if (ctx->base_dir && include_path_normalize(ctx->base_dir, root1, sizeof(root1)) && include_path_within(norm, root1))
            inside = true;
        if (!inside && ctx->directory && ctx->directory[0] &&
            include_path_normalize(ctx->directory, root2, sizeof(root2)) && include_path_within(norm, root2))
            inside = true;
    }
    if (!inside) {
        if (err) {
            snprintf(err->detail, sizeof(err->detail),
                     "$INCLUDE '%.200s' is outside the directories opened at startup (zone file dir%s): the sandboxed server can read "
                     "only below them",
                     path, ctx->directory && ctx->directory[0] ? ", directory" : "");
            err->error_message = err->detail;
        }
        return NULL;
    }
    return strdup(norm);
too_long:
    if (err) err->error_message = "$INCLUDE path too long";
    return NULL;
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

/* An error in the RFC 3597 generic RDATA of the record whose type token is `type`: the message, and the position of the
 * record in `buf` so that the error is reported at its own line (the other record errors point at the type token). */
static void zone_generic_rdata_error(parse_context_t *ctx, const char *type, const char *buf, const char *msg) {
  if (!ctx || !ctx->err_out) return;
  ctx->err_out->error_message = msg;
  if (type && buf && type >= buf) {
    ctx->err_out->error_offset = (size_t)(type - buf);
    ctx->err_out->token_length = strlen(type);
  }
}

/* B9a: the PowerDNS record types ALIAS and LUA.  Neither is an IETF type; PowerDNS keeps them as TYPE65401 (ALIAS: RDATA =
 * the target name, uncompressed) and TYPE65402 (LUA: RDATA = the 16-bit type, then the code as <character-string>s) and sends
 * them like that in a zone transfer (design 3.6b), so a zone file written with the mnemonics is turned into exactly that
 * RFC 3597 generic form here.  Both are private use type codes (RFC 6895 section 3.1) of CLASS IN; KariDNS's own Extended
 * AXFR records use the same numbers in CLASS 65302 (DNS_CLASS_KARIDNS_EXT), so everything that tells them apart looks at the
 * pair (type, class).  ALIAS <target> / LUA <type> "<code>" ["<more code>" ...]; names are not compressed (RFC 3597 section 4). */
static int zone_pdns_type_rewrite(dns_record_t *rec, bool is_alias, const char *origin, zone_arena_t *arena,
                                  parse_context_t *ctx, const char *buf) {
  uint8_t *rd = (uint8_t *)malloc(65536);
  char *hex = NULL;
  const char *why = NULL;
  size_t n = 0;
  if (!rd) {
    zone_generic_rdata_error(ctx, rec->type, buf, "Out of memory");
    return -1;
  }
  if (is_alias) {
    if (rec->rdata_count != 1) {
      why = "ALIAS needs exactly one target name";
    } else {
      char *name = expand_domain_name(rec->rdata[0], origin, arena);
      if (!name || strcmp(name, ".") == 0 || !validate_domain_name_length(name, NULL, NULL, NULL)) {
        why = "ALIAS target is not a valid domain name";
      } else {
        long w = write_uncompressed_name_ext(rd, 0, 256, name, false);
        if (w <= 0) why = "ALIAS target is not a valid domain name";
        else n = (size_t)w;
      }
    }
  } else {
    uint16_t qt = rec->rdata_count >= 2 ? get_type_code(rec->rdata[0]) : 0;
    if (rec->rdata_count < 2) {
      why = "LUA needs a record type and the code as a quoted string";
    } else if (qt == 0 || is_meta_rrtype(qt)) {
      why = "LUA: the first field must be a record type (A, TXT, TYPEnnn, ...)";
    } else {
      rd[n++] = (uint8_t)(qt >> 8);
      rd[n++] = (uint8_t)qt;
      for (int j = 1; j < rec->rdata_count && !why; j++) {
        unescape_string_in_place(rec->rdata[j]);
        size_t len = strlen(rec->rdata[j]);
        size_t off = 0;
        do {                      /* a string longer than 255 octets is cut into <character-string>s, as PowerDNS does */
          size_t chunk = len - off > 255 ? 255 : len - off;
          if (n + 1 + chunk > 65535) { why = "LUA code is too long (RDATA above 65535 octets)"; break; }
          rd[n++] = (uint8_t)chunk;
          memcpy(rd + n, rec->rdata[j] + off, chunk);
          n += chunk;
          off += chunk;
        } while (off < len);
      }
    }
  }
  if (!why) {
    hex = (char *)arena_alloc(arena, n * 2 + 1);
    char *lenstr = (char *)arena_alloc(arena, 8);
    if (!hex || !lenstr || !arena_record_alloc_rdata(arena, rec, 3)) {
      why = "Out of memory";
    } else {
      static const char digits[] = "0123456789abcdef";
      for (size_t i = 0; i < n; i++) {
        hex[2 * i] = digits[rd[i] >> 4];
        hex[2 * i + 1] = digits[rd[i] & 15];
      }
      hex[2 * n] = '\0';
      snprintf(lenstr, 8, "%zu", n);
      rec->rdata[0] = arena_strdup(arena, "\\#");
      rec->rdata[1] = lenstr;
      rec->rdata[2] = hex;
      rec->rdata_count = 3;
      rec->type = arena_strdup(arena, is_alias ? "TYPE65401" : "TYPE65402");
      if (!rec->rdata[0] || !rec->type) why = "Out of memory";
    }
  }
  free(rd);
  if (why) {
    zone_generic_rdata_error(ctx, rec->type, buf, why);
    return -1;
  }
  return 0;
}

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
    if (arena->file_buf_count >= ZONE_ARENA_MAX_FILES) {
        if (ctx->err_out) ctx->err_out->error_message = "Too many $INCLUDE files (max 32)";
        return -1;
    }

    char *resolved = resolve_include_path(ctx, fields[1]);
    if (!resolved) {
        if (ctx->err_out) {
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

    if (zone_arena_add_file(arena, file_content, display_copy, resolved) != 0) {
        free(file_content);
        free(display_copy);
        free(resolved);
        if (ctx->err_out) ctx->err_out->error_message = "Out of memory";
        return -1;
    }

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
    child_ctx.cur_file = resolved;
    zone_parse_state_t child_st = *st;
    child_st.origin_io = &child_origin;

    int rc = parse_zone_buffer(file_content, strlen(file_content), arena, &child_ctx, &child_st, false);
    ctx->no_ttl_count = child_ctx.no_ttl_count;               /* the child worked on a copy */
    ctx->first_no_ttl_owner = child_ctx.first_no_ttl_owner;
    ctx->first_no_ttl_file = child_ctx.first_no_ttl_file;
    ctx->first_no_ttl_line = child_ctx.first_no_ttl_line;
    ctx->long_txt_count = child_ctx.long_txt_count;
    ctx->first_long_txt_owner = child_ctx.first_long_txt_owner;
    ctx->first_long_txt_file = child_ctx.first_long_txt_file;
    ctx->first_long_txt_line = child_ctx.first_long_txt_line;

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

bool arena_record_alloc_rdata(zone_arena_t *arena, dns_record_t *rec, int n) {
  rec->rdata = n > 0 ? arena_alloc(arena, (size_t)n * sizeof(char *)) : NULL;
  if (rec->rdata) memset(rec->rdata, 0, (size_t)n * sizeof(char *));   /* 書かなかった要素は NULL (従来の配列と同じ) */
  return n <= 0 || rec->rdata != NULL;
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

/* The class of a record as BIND 9.20 prints it in "class '%s' != zone class '%s'" (lib/dns/master.c load_text(), DNS_R_BADCLASS). */
static void zone_class_name(uint16_t cls, char out[16]) {
    if (cls == 1) strcpy(out, "IN");
    else if (cls == 3) strcpy(out, "CH");
    else if (cls == 4) strcpy(out, "HS");
    else snprintf(out, 16, "CLASS%u", (unsigned)cls);
}

/* TXT-like types: one or more <character-string>s (RFC 1035 section 3.3.14; SPF 99, NINFO 56, AVC 258, RESINFO 261, WALLET 262 have the same form) */
static bool zone_txt_like(uint16_t t) {
    return t == 16 || t == 99 || t == 56 || t == 258 || t == 261 || t == 262;
}

/* A record with a character-string over 255 octets (split below / by the encoder): counted so that karicheck can warn that BIND refuses it */
static void note_long_txt(parse_context_t *ctx, const char *owner) {
    if (!ctx) return;
    if (ctx->long_txt_count == 0) {
        ctx->first_long_txt_owner = owner;
        ctx->first_long_txt_file = ctx->cur_file;
        ctx->first_long_txt_line = ctx->cur_line;
    }
    ctx->long_txt_count++;
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
            int64_t offset = 0;
            int width = 0;
            char base = 'd';
            if (*p == '{') {
                char *end;
                errno = 0;
                long long ov = strtoll(p + 1, &end, 10);
                p = end;
                /* BIND は offset を int で持つ。範囲外は黙って丸めず拒否する (value + offset の符号付き
                 * オーバーフロー = UB も、これで起きない: value は 32 bit に収まる) */
                if (errno == ERANGE || ov < INT32_MIN || ov > INT32_MAX) {
                    if (err_out) err_out->error_message = "$GENERATE offset out of range (32-bit signed)";
                    return (size_t)-1;
                }
                offset = ov;
                if (*p == ',') {
                    errno = 0;
                    long wv = strtol(p + 1, &end, 10);
                    p = end;
                    if (errno == ERANGE || wv < 0 || wv > 64) {
                        if (err_out) err_out->error_message = "$GENERATE width out of range (0-64)";
                        return (size_t)-1;
                    }
                    width = (int)wv;
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
    if (get_type_code(type_str) == 0 && strcasecmp(type_str, "ALIAS") != 0 && strcasecmp(type_str, "LUA") != 0) {
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
        bool was_gen = ctx && ctx->in_generate;
        if (ctx) ctx->in_generate = true;           /* the generated records are on the line of the $GENERATE statement */
        int grc = parse_zone_buffer(line, (size_t)line_len, arena, ctx, &gen_st, false);
        if (ctx) ctx->in_generate = was_gen;
        if (grc < 0) {
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

/* RDATA の最後のフィールドが空白で分割できる base64 / 16 進の値である型について、その前にあるフィールド数を返す
 * (それ以外の型は -1)。 */
static int trailing_blob_lead_fields(uint16_t type_code) {
  switch (type_code) {
  case 24: case 46:                 // SIG, RRSIG: 署名 (base64)
    return 8;
  case 25: case 48: case 60:        // KEY, DNSKEY, CDNSKEY: 公開鍵 (base64)
  case 43: case 59:                 // DS, CDS: ダイジェスト (16 進)
  case 32768: case 32769:           // TA, DLV: ダイジェスト (16 進)
  case 37:                          // CERT: 証明書 (base64)
  case 52: case 53:                 // TLSA, SMIMEA: 関連データ (16 進)
    return 3;
  case 49: case 61:                 // DHCID, OPENPGPKEY: RDATA 全体が base64
  case 31: case 32:                 // EID, NIMLOC: RDATA 全体が 16 進 (BIND eid_31.c / nimloc_32.c は 1 個以上のトークンを連結する)
    return 0;
  default:
    return -1;
  }
}

/* fields[from] .. fields[count - 1] を fields[from] に詰めて連結し、新しいフィールド数 (from + 1) を返す。
 * 各フィールドはバッファ内で後ろほど大きなアドレスにある NUL 終端の文字列なので、その場で前へ詰められる。 */
static int join_trailing_fields(char **fields, int from, int count) {
  char *dst = fields[from] + strlen(fields[from]);
  for (int j = from + 1; j < count; j++) {
    size_t len = strlen(fields[j]);
    memmove(dst, fields[j], len);
    dst += len;
  }
  *dst = '\0';
  return from + 1;
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
  size_t line_no = 1, rec_line = 1;   /* line of p, and the line the record being read starts on (only '\n' counts: the buffer is cut in place) */

STATE_START_LINE:
  if (p >= end)
    goto DONE;
  rec_line = line_no;
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
    if (*p == '\n') line_no++;
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
      if (p < end) {
        if (*p == '\n') line_no++;
        p++;
      }
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
  if (delimiter == '\n') line_no++;
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
  if (ctx && !ctx->in_generate) ctx->cur_line = rec_line;
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
    /* BIND 9.20 ARM 3.5.5.4: "Valid TTLs are of the range 0-2147483647 seconds"; a value that is not a TTL is an error (it used to
     * become 3600 without a word) */
    uint32_t dtv;
    if (field_idx < 2 || !parse_ttl_strict(fields[1], 2147483647u, &dtv)) {
      if (ctx && ctx->err_out) {
        ctx->err_out->error_message = field_idx < 2 ? "$TTL requires a value"
                                                    : "Invalid $TTL value (expected 0-2147483647 seconds, or units such as 1h30m)";
        ctx->err_out->error_offset = (size_t)((field_idx < 2 ? fields[0] : fields[1]) - buf);
        ctx->err_out->token_length = strlen(field_idx < 2 ? fields[0] : fields[1]);
      }
      return -1;
    }
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
  {
    /* The zone has one class: the class of its first record.  BIND takes it from the configuration and refuses a record of another class
     * ("class 'CH' != zone class 'IN'", lib/dns/master.c load_text(), DNS_R_BADCLASS); a record without a class has the zone's. */
    uint16_t zclass = arena->count > 1 ? arena->records[0].class_val : 0;
    if (zclass != 0) {
      if (rec->class_str && class_val != zclass) {
        if (ctx && ctx->err_out) {
          char a[16], b[16];
          zone_class_name(class_val, a);
          zone_class_name(zclass, b);
          snprintf(ctx->err_out->detail, sizeof(ctx->err_out->detail), "class '%s' != zone class '%s'", a, b);
          ctx->err_out->error_message = ctx->err_out->detail;
          ctx->err_out->error_offset = (size_t)(rec->class_str - buf);
          ctx->err_out->token_length = strlen(rec->class_str);
        }
        return -1;
      }
      class_val = zclass;
    }
  }
  /* 末尾が base64 / 16 進の 1 フィールド (鍵・署名・ダイジェスト) の型は、その値を空白で区切って何行にも分けて
   * 書ける (RFC 4034 §2.2/§3.2 等)。ML-DSA-44 (algorithm 18) の RRSIG 署名は base64 で 3228 文字あり、
   * dnssec-signzone などの出力では MAX_RDATA を超える数の断片に分かれるので、超えるときは末尾の断片を
   * 1 フィールドに連結する (エンコーダは断片を連結して復号するので、結果のワイヤ形式は変わらない)。 */
  int txt_wire_from = -1, txt_wire_to = -1;   /* I5: a TXT-like RR with more character-strings than MAX_RDATA */
  if (field_idx - i > MAX_RDATA && rec->type) {
    uint16_t tc = get_type_code(rec->type);
    int lead = trailing_blob_lead_fields(tc);
    /* "\# <len> <hex>" (RFC 3597 §5) of a whole-RDATA blob type: its tokens are the length and the hex, not one value to join */
    bool generic_tok = strcmp(fields[i], "\\#") == 0 || strcmp(fields[i], "#") == 0;
    if (generic_tok) {
      /* RFC 3597 section 5: "\# <length> <hex>", the hex digits in any number of tokens, for every type: they are the RDATA octets, whatever
       * the type's own text form is, so the tokens after the length are joined into one (dns_generic_rdata_parse() reads them as one) */
      if (i + 2 < field_idx) field_idx = join_trailing_fields(fields, i + 2, field_idx);
    } else if (lead >= 0 && i + lead < field_idx)
      field_idx = join_trailing_fields(fields, i + lead, field_idx);
    else if (zone_txt_like(tc) && !generic_tok) {
      /* I5, RFC 1035 §3.3.14: TXT (and SPF, NINFO, AVC, RESINFO, WALLET, the same wire form) is "one or more <character-string>s" with no
       * count; more strings than the text fields hold are encoded straight into the wire form below (the RR is served and
       * transferred as it is, like one with a NUL octet from a transfer), not refused */
      txt_wire_from = i;
      txt_wire_to = field_idx;
      field_idx = i;
    }
  }
  /* S5: rdata[] は個数ぶんだけ arena に持つ (EID/NIMLOC の書き換えだけは下で 3 個の配列に取り直す) */
  {
    int nrd = field_idx - i < MAX_RDATA ? field_idx - i : MAX_RDATA;
    if (nrd > 0) {
      if (!arena_record_alloc_rdata(arena, rec, nrd)) {
        if (ctx && ctx->err_out) {
          ctx->err_out->error_message = "Out of memory";
          ctx->err_out->error_offset = (size_t)(fields[i] - buf);
          ctx->err_out->token_length = strlen(fields[i]);
        }
        return -1;
      }
    }
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
  
  if (strcasecmp(rec->type, "ALIAS") == 0 || strcasecmp(rec->type, "LUA") == 0) {
    if (zone_pdns_type_rewrite(rec, toupper((unsigned char)rec->type[0]) == 'A', *origin_io, arena, ctx, buf) != 0)
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
  uint32_t ttl_val = 0;
  bool ttl_val_known = false;
  if (explicit_ttl) {
    if (!parse_ttl_strict(explicit_ttl, 2147483647u, &ttl_val)) {
      if (ctx && ctx->err_out) {
        ctx->err_out->error_message = "Invalid TTL (expected 0-2147483647 seconds, or units such as 1h30m)";
        ctx->err_out->error_offset = (size_t)(explicit_ttl - buf);
        ctx->err_out->token_length = strlen(explicit_ttl);
      }
      return -1;
    }
    ttl_val_known = true;
  }
  /* The SOA fields refresh, retry, expire and minimum are written like TTLs (RFC 1035 §3.3.13; BIND parses them with
   * dns_ttl_fromtext): text that is not a number with optional units used to become 3600 in the SOA. */
  if (rec->type_code == 6 && rec->rdata_count == 7) {
    /* the serial is a plain number up to 4294967295 (BIND soa_6.c fromtext_soa: a number token, then uint32_tobuffer); anything else rejects
     * the zone in BIND, here it used to be read as 0 or truncated */
    uint32_t serial_v;
    int serial_err;
    if (!parse_soa_serial_strict(rec->rdata[2], &serial_v, &serial_err)) {
      if (ctx && ctx->err_out) {
        ctx->err_out->error_message = serial_err == 2 ? "SOA serial out of range (expected 0-4294967295)"
                                                      : "Invalid SOA serial (expected a number 0-4294967295)";
        ctx->err_out->error_offset = (size_t)(rec->rdata[2] - buf);
        ctx->err_out->token_length = strlen(rec->rdata[2]);
      }
      return -1;
    }
    for (int sf = 3; sf <= 6; sf++) {
      uint32_t sv;
      if (!parse_ttl_strict(rec->rdata[sf], 0xFFFFFFFFu, &sv)) {
        if (ctx && ctx->err_out) {
          ctx->err_out->error_message = "Invalid SOA refresh/retry/expire/minimum value (expected a number, or units such as 1h30m)";
          ctx->err_out->error_offset = (size_t)(rec->rdata[sf] - buf);
          ctx->err_out->token_length = strlen(rec->rdata[sf]);
        }
        return -1;
      }
    }
  }
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
  if (ttl_val_known) {
    rec->ttl_value = ttl_val;
  } else if (rec->ttl) {
    /* $TTL and the earlier explicit TTLs were checked when they were read; the SOA minimum above (0xFFFFFFFF allowed there) is
     * clamped to 2147483647 like a transferred one (RFC 8767 §4) */
    rec->ttl_value = parse_ttl_value(rec->ttl);
  } else {
    rec->ttl_value = 3600;
    if (ctx) {
      if (ctx->no_ttl_count == 0) {
        ctx->first_no_ttl_owner = rec->name;
        ctx->first_no_ttl_file = ctx->cur_file;
        ctx->first_no_ttl_line = ctx->cur_line;
      }
      ctx->no_ttl_count++;
    }
  }
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

  if (zone_txt_like(rec->type_code) && !(rec->rdata_count >= 1 && (strcmp(rec->rdata[0], "\\#") == 0 || strcmp(rec->rdata[0], "#") == 0))) {
    for (int j = 0; j < rec->rdata_count; j++) {
      if (strlen(rec->rdata[j]) > 255) {
        note_long_txt(ctx, rec->name);
        break;
      }
    }
  }

  rec->generic_len = 0;
  rec->generic_data = NULL;
  if (txt_wire_from >= 0) {
    /* I5: the character-strings of a long TXT, each unescaped and cut into 255-octet pieces as serialize_dns_record()
     * does for the text fields, kept as the RDATA octets (RFC 3597 §5 form; the whole RDATA fits a 16-bit RDLENGTH) */
    uint8_t *blob = (uint8_t *)malloc(65535);
    size_t glen = 0;
    bool long_noted = false;
    if (!blob) {
      zone_generic_rdata_error(ctx, rec->type, buf, "Out of memory");
      return -1;
    }
    for (int j = txt_wire_from; j < txt_wire_to; j++) {
      unescape_string_in_place(fields[j]);
      size_t len = strlen(fields[j]);
      if (len > 255 && !long_noted) {
        note_long_txt(ctx, rec->name);
        long_noted = true;
      }
      const char *s = fields[j];
      do {
        size_t piece = len > 255 ? 255 : len;
        if (glen + 1 + piece > 65535) {
          free(blob);
          zone_generic_rdata_error(ctx, rec->type, buf, "TXT RDATA longer than 65535 octets");
          return -1;
        }
        blob[glen++] = (uint8_t)piece;
        memcpy(blob + glen, s, piece);
        glen += piece;
        s += piece;
        len -= piece;
      } while (len > 0);
    }
    uint8_t *keep = (uint8_t *)arena_alloc(arena, glen);
    if (!keep) {
      free(blob);
      zone_generic_rdata_error(ctx, rec->type, buf, "Out of memory");
      return -1;
    }
    memcpy(keep, blob, glen);
    free(blob);
    rec->generic_data = keep;
    rec->generic_len = (uint16_t)glen;
    rec->rdata_count = 0;
  }
  /* Types BIND takes only in the RFC 3597 "\# <len> <hex>" form.  NULL (10): null_10.c fromtext_null() always returns
   * DNS_R_SYNTAX.  UINFO/UID/GID/UNSPEC (100-103): BIND 9.18/9.20 gen.c registers only the names (no rdata module), so
   * dns_rdata_fromtext() gives DNS_R_UNKNOWN for anything but "\#".  Text fields could not be encoded for them (the lint
   * pass would only report "cannot be serialized"), so the line is refused here, as BIND refuses the zone. */
  bool generic_form = rec->rdata_count >= 1 && (strcmp(rec->rdata[0], "\\#") == 0 || strcmp(rec->rdata[0], "#") == 0);
  if (!generic_form && (rec->type_code == 10 || (rec->type_code >= 100 && rec->type_code <= 103))) {
    zone_generic_rdata_error(ctx, rec->type, buf, "This record type has no text form; write the RDATA in the RFC 3597 \\# form");
    return -1;
  }
  /* EID (31) / NIMLOC (32) have no dedicated wire encoder; the server always serves them via the RFC 3597 generic form.
   * Their text form (BIND in_1/eid_31.c, nimloc_32.c fromtext: isc_hex_tobuffer(lexer, target, isc_one_or_more)) is hex
   * digits in one or more tokens with no "\# len" prefix: the tokens are concatenated, an odd number of digits or a
   * non-hex character is refused, and the result is rewritten into an equivalent "\# <len> <hex>" generic record. */
  if ((rec->type_code == 31 || rec->type_code == 32) && !generic_form) {
    size_t hexlen = 0;
    const char *bad = NULL;
    for (int j = 0; j < rec->rdata_count; j++) {
      size_t l = strlen(rec->rdata[j]);
      if (strspn(rec->rdata[j], "0123456789abcdefABCDEF") != l) bad = "EID/NIMLOC RDATA contains a non-hexadecimal character";
      hexlen += l;
    }
    if (!bad && hexlen == 0) bad = "EID/NIMLOC RDATA is empty";
    else if (!bad && (hexlen % 2) != 0) bad = "EID/NIMLOC RDATA has an odd number of hex digits";
    else if (!bad && hexlen / 2 > 65535) bad = "EID/NIMLOC RDATA is longer than 65535 octets";
    if (bad) {
      zone_generic_rdata_error(ctx, rec->type, buf, bad);
      return -1;
    }
    char lenbuf[16];
    snprintf(lenbuf, sizeof(lenbuf), "%zu", hexlen / 2);
    char *joined = (char *)arena_alloc(arena, hexlen + 1);
    char *lenstr = arena_strdup(arena, lenbuf);
    char *marker = arena_strdup(arena, "\\#");
    if (!joined || !lenstr || !marker) {
      zone_generic_rdata_error(ctx, rec->type, buf, "Out of memory");
      return -1;
    }
    size_t w = 0;
    for (int j = 0; j < rec->rdata_count; j++) {
      size_t l = strlen(rec->rdata[j]);
      memcpy(joined + w, rec->rdata[j], l);
      w += l;
    }
    joined[w] = '\0';
    if (!arena_record_alloc_rdata(arena, rec, 3)) return -1;
    rec->rdata[0] = marker;
    rec->rdata[1] = lenstr;
    rec->rdata[2] = joined;
    rec->rdata_count = 3;
  }
  if (rec->rdata_count >= 2 && (strcmp(rec->rdata[0], "\\#") == 0 || strcmp(rec->rdata[0], "#") == 0)) {
    /* RFC 3597 section 5: "\# <length> <hex rdata>". The declared length is a decimal number, the rdata is an
     * even number of hex digits (possibly split into several tokens) and its size MUST equal <length>. Anything
     * else used to be "repaired" silently (non-hex skipped, short data padded, long data cut off), which let a
     * malformed record be served as if it were valid (e.g. a 3-byte A record). */
    /* One implementation with dag's UPDATE operands: dns_generic_rdata_parse() (length, hex, fixed sizes, and the
     * D15-2 rule that the RDATA must be valid for the type). */
    uint8_t *tmp = (uint8_t *)malloc(65535);
    if (!tmp) {
      zone_generic_rdata_error(ctx, rec->type, buf, "Out of memory");
      return -1;
    }
    size_t glen = 0;
    const char *gwhy = dns_generic_rdata_parse(rec->type_code, rec->rdata, rec->rdata_count, tmp, &glen);
    if (gwhy) {
      free(tmp);
      zone_generic_rdata_error(ctx, rec->type, buf, gwhy);
      return -1;
    }
    rec->generic_len = (uint16_t)glen;
    if (glen > 0) {
      uint8_t *blob = (uint8_t *)arena_alloc(arena, glen);
      if (blob) memcpy(blob, tmp, glen);
      rec->generic_data = blob;
    } else {
      rec->generic_data = (uint8_t *)"";
    }
    free(tmp);
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
int zone_arena_add_file(zone_arena_t *arena, char *buf, char *display, char *path) {
  if (arena->file_buf_count >= ZONE_ARENA_MAX_FILES) return -1;
  if (arena->file_buf_count >= arena->file_buf_cap) {
    /* 1 ファイルのゾーンが大半なので 1 から倍に伸ばす (固定 32 個分を全ゾーンに持たない) */
    int cap = arena->file_buf_cap ? arena->file_buf_cap * 2 : 1;
    if (cap > ZONE_ARENA_MAX_FILES) cap = ZONE_ARENA_MAX_FILES;
    char **b = realloc(arena->file_bufs, (size_t)cap * sizeof(*b));
    if (!b) return -1;
    arena->file_bufs = b;
    char **d = realloc(arena->display_bufs, (size_t)cap * sizeof(*d));
    if (!d) return -1;
    arena->display_bufs = d;
    char **p = realloc(arena->file_paths, (size_t)cap * sizeof(*p));
    if (!p) return -1;
    arena->file_paths = p;
    arena->file_buf_cap = cap;
  }
  arena->file_bufs[arena->file_buf_count] = buf;
  arena->display_bufs[arena->file_buf_count] = display;
  arena->file_paths[arena->file_buf_count] = path;
  arena->file_buf_count++;
  return 0;
}

void zone_arena_free_include_buffers(zone_arena_t *arena) {
  for (int i = 0; i < arena->file_buf_count; i++) {
    free(arena->file_bufs[i]);
    free(arena->display_bufs[i]);
    free(arena->file_paths[i]);
  }
  free(arena->file_bufs);
  free(arena->display_bufs);
  free(arena->file_paths);
  arena->file_bufs = NULL;
  arena->display_bufs = NULL;
  arena->file_paths = NULL;
  arena->file_buf_count = 0;
  arena->file_buf_cap = 0;
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

void zone_arena_free_builder(zone_arena_t *arena) {
  free(arena->records);
  arena->records = NULL;
  arena->count = 0;
  arena->records_cap = 0;
  for (int i = 0; i < arena->data_pool_count; i++)
    free(arena->data_pools[i]);
  free(arena->data_pools);
  arena->data_pools = NULL;
  arena->data_pool_count = 0;
  arena->data_pool_cap = 0;
  arena->current_pool_cap = 0;
  arena->current_pool_idx = 0;
  free(arena->hash_table);
  arena->hash_table = NULL;
  arena->hash_size = 0;
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
  zone_arena_free_include_buffers(arena);
}

void zone_arena_destroy(zone_arena_t *arena) {
  free(arena->image);
  arena->image = NULL;
  zone_arena_free_builder(arena);
  free(arena->glue);
  arena->glue = NULL;
  arena->rcache_ok = false;
  atomic_store_explicit(&arena->generation, 0, memory_order_relaxed);
}

zone_version_t zone_version_empty;

zone_version_t *zone_version_new(zone_arena_t *builder) {
  zone_version_t *v = calloc(1, sizeof(*v));
  if (!v) return NULL;
  v->image = builder->image;
  v->heap = true;
  builder->image = NULL;
  return v;
}

void zone_version_free(zone_version_t *v) {
  if (!v || !v->heap) return;
  free(v->image);
  free(v->glue);
  free(v);
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
  size_t p = 8; /* S4: 小さいゾーンに 1 KiB の表を持たせない (以前は最小 256) */
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
 * B8t-2: only among RRs of the same visibility (dns_record_same_visibility()): an RR that only some clients see (tinydns location or
 * time stamp, $LOCATION / $ECS-SUBNET tag) keeps the TTL it was written with, also when an unrestricted RR of the same name and
 * type exists (tinydns serves each record with its own TTL).  A zone without such RRs is unchanged.
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
      if (!dns_record_same_visibility(rj, ri)) continue;
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
      if (!dns_record_same_visibility(rj, ri)) continue;
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

/* S4: 読み込み中に倍に伸ばした records を件数に合わせて縮める (1 件 sizeof(dns_record_t))。
 * 公開前の arena に、索引を作る前に呼ぶ (レコードへのポインタを持つものがまだ無い) */
void zone_arena_shrink_records(zone_arena_t *arena) {
  if (arena->count > 0 && arena->count < arena->records_cap) {
    dns_record_t *shrunk = realloc(arena->records, arena->count * sizeof(dns_record_t));
    if (shrunk) {
      arena->records = shrunk;
      arena->records_cap = arena->count;
    }
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

/* B9a (design 3.6b): the rules for PowerDNS's ALIAS (TYPE 65401) and LUA (TYPE 65402) records of CLASS IN.  Not the Extended AXFR
 * records of CLASS 65302 that share the numbers.
 *  - the RDATA must be what the types are: ALIAS = one uncompressed domain name filling the RDATA (RFC 3597 section 4); LUA = a
 *    16-bit type and one or more <character-string>s filling the RDATA.
 *  - an ALIAS name must not also have an A or AAAA RRset: the ALIAS stands for those RRsets (PowerDNS has no rule, but the answer would
 *    be one or the other depending on the mode).  Other types (TXT, MX, NS, ...) may coexist.
 *  - a zone with an ALIAS must not hold DNSSEC records (DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM): an expanded answer cannot be signed
 *    offline (a PRESIGNED zone, or a signed zone file, fails).
 * One implementation for the loaders (via zone_image_freeze(), so every path that publishes a zone), the database reader and karicheck.
 * `detail` receives the message, which err->error_message then points to. */
static bool pdns_alias_rdata_ok(const uint8_t *rd, size_t len) {
  size_t p = 0;
  for (;;) {
    if (p >= len) return false;
    uint8_t l = rd[p++];
    if (l == 0) return p == len;
    if (l > 63 || len - p < l) return false;
    p += l;
  }
}

static bool pdns_lua_rdata_ok(const uint8_t *rd, size_t len) {
  if (len < 3) return false;
  size_t p = 2;
  while (p < len) {
    size_t l = rd[p++];
    if (len - p < l) return false;
    p += l;
  }
  return true;
}

/* Singleton types: an owner name has at most one RR of them (BIND 9.20: DNS_RDATATYPEATTR_SINGLETON, enforced by dns_rdataslab_fromrdataset()
 * and dns_rdataslab_merge() with DNS_R_SINGLETON "multiple RRs of singleton type" after duplicates were dropped, so a zone file, a transfer
 * and an UPDATE that would give a name two different ones are all refused; lib/ns/update.c replaces_p() names only CNAME, DNAME, SOA, NSEC,
 * RRSIG, WKS and NSEC3PARAM as replaced, so an UPDATE adding a second one fails instead of replacing).  RESINFO (RFC 9606 section 3) is the
 * one this server knows that BIND marks so (resinfo_261.c RRTYPE_RESINFO_ATTRIBUTES); CNAME, DNAME and SOA have their own rules.  Two RRs
 * with the same RDATA are one RR.  The index must exist (build_zone_index()).  0 = ok, -1 with `detail` filled. */
static int validate_zone_singletons(const zone_arena_t *arena, char *detail, size_t detail_cap) {
  if (!arena->hash_table) return 0;
  uint8_t *ba = NULL, *bb = NULL;
  int rc = 0;
  for (size_t i = 0; i < arena->count && rc == 0; i++) {
    const dns_record_t *a = &arena->records[i];
    if (a->type_code != 261 || !a->name) continue;
    size_t idx = calc_fnv1a_str(a->name) & (arena->hash_size - 1);
    for (int j = arena->hash_table[idx]; j != -1; j = arena->records[j].next_record) {
      const dns_record_t *b = &arena->records[j];
      if ((size_t)j <= i || b->type_code != 261 || !b->name || b->class_val != a->class_val || !domain_names_match_ci(a->name, b->name))
        continue;
      if (!ba) {
        ba = (uint8_t *)malloc(65535);
        bb = (uint8_t *)malloc(65535);
        if (!ba || !bb) {
          snprintf(detail, detail_cap, "out of memory checking the RESINFO records");
          rc = -1;
          break;
        }
      }
      long la = dns_record_canonical_rdata(a, ba, 65535), lb = dns_record_canonical_rdata(b, bb, 65535);
      if (la >= 0 && lb >= 0 && la == lb && memcmp(ba, bb, (size_t)la) == 0) continue;   /* the same RR twice */
      snprintf(detail, detail_cap, "multiple RRs of singleton type: '%.200s' has more than one RESINFO record (RFC 9606 section 3)", a->name);
      rc = -1;
      break;
    }
  }
  free(ba);
  free(bb);
  return rc;
}

int validate_zone_pdns_types(const zone_arena_t *arena, parse_error_t *err, char *detail, size_t detail_cap) {
  if (!arena || !arena->records || arena->count == 0) return 0;
  size_t n_alias = 0;
  bool dnssec = false;
  const char *dnssec_owner = NULL;
  if (validate_zone_singletons(arena, detail, detail_cap) != 0) goto fail;   /* every publish path calls this function (freeze, database reader, karicheck) */
  for (size_t i = 0; i < arena->count; i++) {
    const dns_record_t *r = &arena->records[i];
    if (r->class_val != 1 && r->class_val != 0) continue;
    if (r->type_code == DNS_TYPE_PDNS_ALIAS || r->type_code == DNS_TYPE_PDNS_LUA) {
      bool alias = r->type_code == DNS_TYPE_PDNS_ALIAS;
      if (!r->generic_data || !(alias ? pdns_alias_rdata_ok(r->generic_data, r->generic_len)
                                       : pdns_lua_rdata_ok(r->generic_data, r->generic_len))) {
        snprintf(detail, detail_cap, "%s record at '%.200s' has malformed RDATA (%s)", alias ? "ALIAS" : "LUA", r->name ? r->name : "",
                 alias ? "one uncompressed domain name expected" : "a 16-bit type and <character-string>s expected");
        goto fail;
      }
      if (alias) n_alias++;
    } else if (!dnssec && (r->type_code == 46 || r->type_code == 47 || r->type_code == 48 || r->type_code == 50 || r->type_code == 51)) {
      dnssec = true;
      dnssec_owner = r->name;
    }
  }
  if (n_alias == 0) return 0;
  if (dnssec) {
    snprintf(detail, detail_cap, "the zone has ALIAS records and DNSSEC records (first at '%.200s'): an ALIAS answer cannot be signed offline",
             dnssec_owner ? dnssec_owner : "");
    goto fail;
  }
  /* the owners of the ALIAS records, in a small open-addressing set */
  size_t cap = 16;
  while (cap < n_alias * 2) cap <<= 1;
  const char **set = (const char **)calloc(cap, sizeof(*set));
  if (!set) {
    snprintf(detail, detail_cap, "out of memory checking the ALIAS records");
    goto fail;
  }
  for (size_t i = 0; i < arena->count; i++) {
    const dns_record_t *r = &arena->records[i];
    if (r->type_code != DNS_TYPE_PDNS_ALIAS || (r->class_val != 1 && r->class_val != 0) || !r->name) continue;
    size_t h = dns_name_hash_ci(r->name) & (cap - 1);
    while (set[h] && !domain_names_match_ci(set[h], r->name)) h = (h + 1) & (cap - 1);
    set[h] = r->name;
  }
  const char *bad = NULL;
  for (size_t i = 0; i < arena->count && !bad; i++) {
    const dns_record_t *r = &arena->records[i];
    if ((r->type_code != 1 && r->type_code != 28) || (r->class_val != 1 && r->class_val != 0) || !r->name) continue;
    size_t h = dns_name_hash_ci(r->name) & (cap - 1);
    while (set[h]) {
      if (domain_names_match_ci(set[h], r->name)) { bad = r->name; break; }
      h = (h + 1) & (cap - 1);
    }
  }
  free(set);
  if (bad) {
    snprintf(detail, detail_cap, "'%.200s' has an ALIAS record and an A or AAAA record: the ALIAS stands for those RRsets", bad);
    goto fail;
  }
  return 0;
fail:
  if (err) {
    err->error_message = detail;
    err->error_offset = 0;
    err->token_length = 0;
    err->file_path = NULL;
  }
  return -1;
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

/* X-32: RDATA をワイヤ形式に書けないレコード (パーサは受け付けたが値が型の形式に合わないもの) を取り除く。
 * 残しておくと応答から黙って落ち、AXFR はそのレコードで転送を打ち切る (後ろのレコードが届かない)。
 * zone_arena_drop_out_of_zone() と同じく build_zone_index() より前に呼ぶ。戻り値は取り除いた件数。 */
size_t zone_arena_drop_unencodable(zone_arena_t *arena, void (*report)(const dns_record_t *rec, void *ud), void *ud) {
  if (!arena || !arena->records) return 0;
  /* ゾーンの読み込みはクエリの経路ではないので、作業領域はヒープに 1 回だけ取る */
  uint8_t *buf = malloc(65535);
  if (!buf) return 0;
  size_t kept = 0, dropped = 0;
  for (size_t i = 0; i < arena->count; i++) {
    dns_record_t *r = &arena->records[i];
    if (dns_record_canonical_rdata(r, buf, 65535) < 0) {
      if (report) report(r, ud);
      dropped++;
      continue;
    }
    if (kept != i) arena->records[kept] = *r;
    kept++;
  }
  arena->count = kept;
  free(buf);
  return dropped;
}

/* B8t-1: SOA RRs at the apex */
bool dns_record_is_restricted(const dns_record_t *r) {
  return r->tinydns_loc[0] != 0 || r->tinydns_loc[1] != 0 || r->tinydns_ttd != 0 || r->ecs_subnet_tag != NULL ||
         r->bind_location_tag != NULL;
}

static bool tags_equal_ci(const char *a, const char *b) {
  if (!a || !b) return a == b;
  return strcasecmp(a, b) == 0;
}

bool dns_record_same_visibility(const dns_record_t *a, const dns_record_t *b) {
  return a->tinydns_loc[0] == b->tinydns_loc[0] && a->tinydns_loc[1] == b->tinydns_loc[1] && a->tinydns_ttd == b->tinydns_ttd &&
         a->tinydns_ttl_countdown == b->tinydns_ttl_countdown && tags_equal_ci(a->bind_location_tag, b->bind_location_tag) &&
         tags_equal_ci(a->ecs_subnet_tag, b->ecs_subnet_tag);
}

const dns_record_t *zone_arena_reference_soa(const zone_arena_t *arena, const char *zone) {
  const dns_record_t *first = NULL;
  if (!arena || !arena->records || !zone) return NULL;
  for (size_t i = 0; i < arena->count; i++) {
    const dns_record_t *r = &arena->records[i];
    if (r->type_code != 6 || r->rdata_count < 7 || !r->name || !domain_names_match_ci(r->name, zone)) continue;
    if (!dns_record_is_restricted(r)) return r;
    if (!first) first = r;
  }
  return first;
}

static int zl_cmp_u16(const void *a, const void *b) {
  uint16_t x = *(const uint16_t *)a, y = *(const uint16_t *)b;
  return x < y ? -1 : x > y;
}

/* max-records, max-records-per-type, max-types-per-name, max-zone-ttl (BIND 9.20: lib/dns/zone.c, rbtdb.c overmaxtype(), dns_rdataslab_fromrdataset(),
 * lib/dns/master.c DNS_MASTER_CHECKTTL).  Runs on the built zone (build_zone_index() done: the name hash chains are used to group the records of a
 * name).  Ordinary process code: it allocates, so it is for the load, never for a query. */
int zone_arena_check_limits(const zone_arena_t *arena, const zone_limits_t *lim, char *err, size_t errlen) {
  if (!arena || !arena->records || !lim) return 0;
  if (lim->max_records && arena->count > lim->max_records) {
    snprintf(err, errlen, "the zone has %zu records, more than max-records %llu", arena->count, (unsigned long long)lim->max_records);
    return -1;
  }
  if (lim->max_zone_ttl) {
    for (size_t i = 0; i < arena->count; i++) {
      const dns_record_t *r = &arena->records[i];
      if (r->ttl_value > lim->max_zone_ttl) {
        snprintf(err, errlen, "'%.200s' %.16s has TTL %u, which exceeds the configured max-zone-ttl %u", r->name ? r->name : "?",
                 r->type ? r->type : "", r->ttl_value, lim->max_zone_ttl);
        return -1;
      }
    }
  }
  if ((!lim->max_per_type && !lim->max_types_per_name) || !arena->hash_table || arena->hash_size == 0) return 0;
  uint16_t *types = NULL;
  size_t types_cap = 0;
  int rc = 0;
  for (size_t i = 0; i < arena->count && rc == 0; i++) {
    const dns_record_t *r = &arena->records[i];
    if (!r->name) continue;
    size_t slot = calc_fnv1a_str(r->name) & (arena->hash_size - 1);
    size_t n = 0;
    bool first = true;
    for (int j = arena->hash_table[slot]; j != -1; j = arena->records[j].next_record) {
      const dns_record_t *o = &arena->records[j];
      if (!o->name || !domain_names_match_ci(o->name, r->name)) continue;
      if ((size_t)j < i) { first = false; break; }   /* this name was grouped when its first record was visited */
      if (n == types_cap) {
        size_t nc = types_cap ? types_cap * 2 : 64;
        uint16_t *nt = realloc(types, nc * sizeof(*types));
        if (!nt) { rc = -2; break; }
        types = nt;
        types_cap = nc;
      }
      types[n++] = o->type_code;
    }
    if (rc != 0) break;
    if (!first) continue;
    qsort(types, n, sizeof(*types), zl_cmp_u16);
    size_t ntypes = 0;
    for (size_t k = 0; k < n;) {
      size_t e = k;
      while (e < n && types[e] == types[k]) e++;
      ntypes++;
      if (lim->max_per_type && e - k > lim->max_per_type) {
        snprintf(err, errlen, "'%.200s' has %zu records of type %u, more than max-records-per-type %u", r->name, e - k,
                 (unsigned)types[k], lim->max_per_type);
        rc = -1;
      }
      k = e;
    }
    if (rc == 0 && lim->max_types_per_name && ntypes > lim->max_types_per_name) {
      snprintf(err, errlen, "'%.200s' has %zu record types, more than max-types-per-name %u", r->name, ntypes, lim->max_types_per_name);
      rc = -1;
    }
  }
  free(types);
  if (rc == -2) snprintf(err, errlen, "out of memory checking the limits of the zone");
  return rc == 0 ? 0 : -1;
}

int zone_arena_check_soa_set(const zone_arena_t *arena, const char *zone, char *err, size_t errlen) {
  if (!arena || !arena->records || !zone) return 0;
  size_t nsoa = 0;
  bool restricted = false, signed_zone = false;
  uint32_t serial = 0;
  for (size_t i = 0; i < arena->count; i++) {
    const dns_record_t *r = &arena->records[i];
    if (r->type_code == 46 || r->type_code == 48 || r->type_code == 47 || r->type_code == 50) signed_zone = true;
    if (r->type_code != 6 || !r->name || !domain_names_match_ci(r->name, zone) || r->rdata_count < 3 || !r->rdata[2]) continue;
    uint32_t s = (uint32_t)strtoul(r->rdata[2], NULL, 10);
    if (nsoa++ == 0) {
      serial = s;
    } else if (s != serial) {
      snprintf(err, errlen, "the SOA records of zone '%s' have different serials (%u and %u); a zone has one serial (RFC 2181 §6.1)",
               zone, serial, s);
      return -1;
    }
    if (dns_record_is_restricted(r)) restricted = true;
  }
  if ((restricted || nsoa > 1) && signed_zone) {
    snprintf(err, errlen, "zone '%s' holds DNSSEC records and several or restricted SOA records (location, time stamp, tag); "
             "the signature of the SOA RRset would not hold for every client", zone);
    return -1;
  }
  return 0;
}

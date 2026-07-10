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

int parse_zone_fast(char *buf, size_t size, zone_arena_t *arena, parse_context_t *ctx) {
  char *prev_owner = NULL;
  char *origin = ctx ? (char *)ctx->default_origin : NULL;
  char *default_ttl_str = NULL;
  char **prev_owner_io = &prev_owner;
  char **origin_io = &origin;
  char **default_ttl_str_io = &default_ttl_str;
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
  if (p >= end)
    goto PROCESS_RECORD;
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
  if (fields[0][0] == '$' && strcasecmp(fields[0], "$TTL") == 0) {
    if (field_idx > 1)
      *default_ttl_str_io = fields[1];
    if (p < end)
      goto STATE_START_LINE;
    goto DONE;
  }
  if (arena->count >= arena->records_cap) {
    size_t new_cap = arena->records_cap == 0 ? 16 : arena->records_cap * 2;
    dns_record_t *new_records =
        realloc(arena->records, new_cap * sizeof(dns_record_t));
    if (!new_records) {
      if (ctx && ctx->err_out) {
        ctx->err_out->error_message = "Out of memory";
        ctx->err_out->error_offset = p - buf;
        ctx->err_out->token_length = 1;
      }
      return -1;
    }
    memset(new_records + arena->records_cap, 0,
           (new_cap - arena->records_cap) * sizeof(dns_record_t));
    arena->records = new_records;
    arena->records_cap = new_cap;
  }
  dns_record_t *rec = &arena->records[arena->count++];
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
    rec->generic_len = atoi(rec->rdata[1]);
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
    if (rec->type_code == 5 || rec->type_code == 12 || rec->type_code == 2) {
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
void zone_arena_destroy(zone_arena_t *arena) {
  free(arena->records);
  for (int i = 0; i < arena->data_pool_count; i++)
    free(arena->data_pools[i]);
  free(arena->hash_table);
  for (int i = 0; i < arena->file_buf_count; i++)
    free(arena->file_bufs[i]);
  arena->file_buf_count = 0;
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


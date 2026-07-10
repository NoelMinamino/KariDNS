#include "dns_zone_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

#define IS_SPACE(c) ((c) == ' ' || (c) == '\t')
#define IS_NEWLINE(c) ((c) == '\n' || (c) == '\r')
#define MAX_FIELDS 64

uint16_t get_type_code(const char *type_str) {
  if (!type_str)
    return 0;
  switch (type_str[0]) {
  case 'A':
    if (strcmp(type_str, "A") == 0)
      return 1;
    if (strcmp(type_str, "AAAA") == 0)
      return 28;
    if (strcmp(type_str, "AFSDB") == 0)
      return 18;
    if (strcmp(type_str, "ATMA") == 0)
      return 34;
    if (strcmp(type_str, "A6") == 0)
      return 38;
    if (strcmp(type_str, "APL") == 0)
      return 42;
    if (strcmp(type_str, "ANY") == 0)
      return 255;
    if (strcmp(type_str, "AVC") == 0)
      return 258;
    if (strcmp(type_str, "AMTRELAY") == 0)
      return 260;
    if (strcmp(type_str, "AXFR") == 0)
      return 252;
    break;
  case 'C':
    if (strcmp(type_str, "CNAME") == 0)
      return 5;
    if (strcmp(type_str, "CERT") == 0)
      return 37;
    if (strcmp(type_str, "CDS") == 0)
      return 59;
    if (strcmp(type_str, "CDNSKEY") == 0)
      return 60;
    if (strcmp(type_str, "CSYNC") == 0)
      return 62;
    if (strcmp(type_str, "CAA") == 0)
      return 257;
    break;
  case 'D':
    if (strcmp(type_str, "DS") == 0)
      return 43;
    if (strcmp(type_str, "DNAME") == 0)
      return 39;
    if (strcmp(type_str, "DNSKEY") == 0)
      return 48;
    if (strcmp(type_str, "DHCID") == 0)
      return 49;
    if (strcmp(type_str, "DOA") == 0)
      return 259;
    if (strcmp(type_str, "DLV") == 0)
      return 32769;
    break;
  case 'E':
    if (strcmp(type_str, "EID") == 0)
      return 31;
    if (strcmp(type_str, "EUI48") == 0)
      return 108;
    if (strcmp(type_str, "EUI64") == 0)
      return 109;
    break;
  case 'G':
    if (strcmp(type_str, "GPOS") == 0)
      return 27;
    break;
  case 'H':
    if (strcmp(type_str, "HINFO") == 0)
      return 13;
    if (strcmp(type_str, "HTTPS") == 0)
      return 65;
    if (strcmp(type_str, "HIP") == 0)
      return 55;
    break;
  case 'I':
    if (strcmp(type_str, "ISDN") == 0)
      return 20;
    if (strcmp(type_str, "IPSECKEY") == 0)
      return 45;
    if (strcmp(type_str, "IXFR") == 0)
      return 251;
    break;
  case 'K':
    if (strcmp(type_str, "KEY") == 0)
      return 25;
    if (strcmp(type_str, "KX") == 0)
      return 36;
    break;
  case 'L':
    if (strcmp(type_str, "LOC") == 0)
      return 29;
    if (strcmp(type_str, "L32") == 0)
      return 105;
    if (strcmp(type_str, "L64") == 0)
      return 106;
    if (strcmp(type_str, "LP") == 0)
      return 107;
    break;
  case 'M':
    if (strcmp(type_str, "MX") == 0)
      return 15;
    if (strcmp(type_str, "MD") == 0)
      return 3;
    if (strcmp(type_str, "MF") == 0)
      return 4;
    if (strcmp(type_str, "MB") == 0)
      return 7;
    if (strcmp(type_str, "MG") == 0)
      return 8;
    if (strcmp(type_str, "MR") == 0)
      return 9;
    if (strcmp(type_str, "MINFO") == 0)
      return 14;
    if (strcmp(type_str, "MAILB") == 0)
      return 253;
    if (strcmp(type_str, "MAILA") == 0)
      return 254;
    break;
  case 'N':
    if (strcmp(type_str, "NS") == 0)
      return 2;
    if (strcmp(type_str, "NULL") == 0)
      return 10;
    if (strcmp(type_str, "NSAP") == 0)
      return 22;
    if (strcmp(type_str, "NSAP-PTR") == 0)
      return 23;
    if (strcmp(type_str, "NXT") == 0)
      return 30;
    if (strcmp(type_str, "NIMLOC") == 0)
      return 32;
    if (strcmp(type_str, "NAPTR") == 0)
      return 35;
    if (strcmp(type_str, "NSEC") == 0)
      return 47;
    if (strcmp(type_str, "NSEC3") == 0)
      return 50;
    if (strcmp(type_str, "NSEC3PARAM") == 0)
      return 51;
    if (strcmp(type_str, "NID") == 0)
      return 104;
    break;
  case 'O':
    if (strcmp(type_str, "OPT") == 0)
      return 41;
    if (strcmp(type_str, "OPENPGPKEY") == 0)
      return 61;
    break;
  case 'P':
    if (strcmp(type_str, "PTR") == 0)
      return 12;
    if (strcmp(type_str, "PX") == 0)
      return 26;
    break;
  case 'R':
    if (strcmp(type_str, "RP") == 0)
      return 17;
    if (strcmp(type_str, "RT") == 0)
      return 21;
    if (strcmp(type_str, "RRSIG") == 0)
      return 46;
    break;
  case 'S':
    if (strcmp(type_str, "SOA") == 0)
      return 6;
    if (strcmp(type_str, "SRV") == 0)
      return 33;
    if (strcmp(type_str, "SIG") == 0)
      return 24;
    if (strcmp(type_str, "SINK") == 0)
      return 40;
    if (strcmp(type_str, "SSHFP") == 0)
      return 44;
    if (strcmp(type_str, "SMIMEA") == 0)
      return 53;
    if (strcmp(type_str, "SVCB") == 0)
      return 64;
    if (strcmp(type_str, "SPF") == 0)
      return 99;
    break;
  case 'T':
    if (strcmp(type_str, "TXT") == 0)
      return 16;
    if (strcmp(type_str, "TLSA") == 0)
      return 52;
    if (strcmp(type_str, "TKEY") == 0)
      return 249;
    if (strcmp(type_str, "TSIG") == 0)
      return 250;
    if (strcmp(type_str, "TA") == 0)
      return 32768;
    if (strncmp(type_str, "TYPE", 4) == 0)
      return (uint16_t)atoi(type_str + 4);
    break;
  case 'U':
    if (strcmp(type_str, "URI") == 0)
      return 256;
    break;
  case 'W':
    if (strcmp(type_str, "WKS") == 0)
      return 11;
    break;
  case 'X':
    if (strcmp(type_str, "X25") == 0)
      return 19;
    break;
  case 'Z':
    if (strcmp(type_str, "ZONEMD") == 0)
      return 63;
    break;
  }
  return 0;
}

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


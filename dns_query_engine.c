#define OPENSSL_SUPPRESS_DEPRECATED 1
#include "dns_query_engine.h"
#include "dns_server_internal.h"
#include "dns_catalog_zone.h"
#include "dns_dnstap.h"
#include "dns_edns_ecs.h"
#include "dns_rrl.h"
#include "dns_tsig_acl.h"
#include "dns_priv_sandbox.h"
#include "dns_dynamic_update.h"

#ifdef __FreeBSD__
#include <sys/capsicum.h>
#include <sys/event.h>
#endif

#define STATIC_TEST

program_plugin_t *g_program_plugins = NULL;
int g_program_plugins_count = 0;

static bool attach_covering_rrsig_ext(zone_arena_t *zone, size_t hash_idx,
                                      const char *match_name,
                                      const char *owner_name_override,
                                      uint16_t type_covered, uint8_t *res,
                                      size_t max_res_len, uint16_t *offset,
                                      compress_ctx_t *comp_ctx, uint16_t *count,
                                      uint32_t override_ttl) {
  for (int i = zone->hash_table[hash_idx]; i != -1;
       i = zone->records[i].next_record) {
    dns_record_t *rec = &zone->records[i];
    if (rec->type_code != 46 /* RRSIG */ ||
        strcasecmp(rec->name, match_name) != 0)
      continue;
    if (rec->rdata_count < 9) // Type Covered..Signatureまでの必須フィールド数
      continue; // 壊れたRRSIGは無視してスキップ(致命的にしない)
    if (get_type_code(rec->rdata[0]) != type_covered)
      continue;
    if (serialize_dns_record(res, max_res_len, offset, rec, comp_ctx,
                             owner_name_override, override_ttl) < 0)
      return false; // バッファ溢れのみ呼び出し元に伝える
    (*count)++;
    // 鍵ロールオーバー中は同一タイプに複数のRRSIGが存在し得るためbreakしない
  }
  return true;
}

static inline bool attach_covering_rrsig(zone_arena_t *zone, size_t hash_idx,
                                         const char *match_name,
                                         const char *owner_name_override,
                                         uint16_t type_covered, uint8_t *res,
                                         size_t max_res_len, uint16_t *offset,
                                         compress_ctx_t *comp_ctx, uint16_t *count) {
  return attach_covering_rrsig_ext(zone, hash_idx, match_name, owner_name_override,
                                   type_covered, res, max_res_len, offset, comp_ctx, count,
                                   0xFFFFFFFF);
}

static bool zone_uses_nsec3(zone_arena_t *zone, const char *apex_name) {
  uint32_t apex_hash = calc_fnv1a_str(apex_name);
  size_t apex_idx = apex_hash & (zone->hash_size - 1);
  for (int i = zone->hash_table[apex_idx]; i != -1;
       i = zone->records[i].next_record) {
    dns_record_t *rec = &zone->records[i];
    if (rec->type_code == 51 /* NSEC3PARAM */ &&
        domain_names_match_ci(rec->name, apex_name))
      return true;
  }
  return false;
}

static bool is_non_data_rrtype(uint16_t t) {
    switch (t) {
        case 41: case 249: case 250: case 251: case 252: case 253: case 254: case 255:
            return true;
        default:
            return false;
    }
}

static resolve_checkpoint_t save_checkpoint(uint16_t *offset, uint16_t *ancount,

                                             uint16_t *nscount, uint16_t *arcount) {
    resolve_checkpoint_t cp = { *offset, *ancount, *nscount, *arcount };
    return cp;
}

STATIC_TEST void restore_checkpoint(const resolve_checkpoint_t *cp, uint16_t *offset,
                                uint16_t *ancount, uint16_t *nscount, uint16_t *arcount) {
    *offset = cp->offset;
    *ancount = cp->ancount;
    *nscount = cp->nscount;
    *arcount = cp->arcount;
}

/* レコードが「今このクエリ時点で」応答に含めるべきかを判定する。
 * 含めるべきならtrueを返し、*effective_ttl_out に配信すべきTTLを書く
 * (通常のレコードならrec->ttl_valueをそのままコピーするだけ)。
 * 含めるべきでなければfalseを返す(呼び出し側はこのレコードを無視する)。
 *
 * rec->tinydns_ttd == 0 かつ location未指定・ECSタグ未指定・LOCATIONタグ未指定の場合(制限のないレコード)
 * は即座にtrueを返す。 */
STATIC_TEST bool tinydns_record_currently_valid(const dns_record_t *rec, time_t now,
                                                const char client_loc[2],
                                                const char *client_ecs_tag,
                                                const char *client_loc_tag,
                                                uint32_t *effective_ttl_out) {
    if (rec->tinydns_loc[0] != 0 || rec->tinydns_loc[1] != 0) {
        if (rec->tinydns_loc[0] != client_loc[0] || rec->tinydns_loc[1] != client_loc[1]) {
            return false;
        }
    }
    if (rec->ecs_subnet_tag != NULL) {
        if (client_ecs_tag == NULL || strcasecmp(rec->ecs_subnet_tag, client_ecs_tag) != 0) {
            return false;
        }
    }
    if (rec->bind_location_tag != NULL) {
        if (client_loc_tag == NULL || strcasecmp(rec->bind_location_tag, client_loc_tag) != 0) {
            return false;
        }
    }
    if (rec->tinydns_ttd == 0) {
        *effective_ttl_out = rec->ttl_value;
        return true;
    }

    if (!rec->tinydns_ttl_countdown) {
        /* アクティベーション時刻としてのtimestamp */
        if (rec->tinydns_ttd >= now) return false; /* まだ未来 */
        *effective_ttl_out = rec->ttl_value;
        return true;
    }

    /* カウントダウンTTL(有効期限としてのtimestamp)。 */
    if (rec->tinydns_ttd < now) return false; /* 既に期限切れ */
    double remaining = difftime(rec->tinydns_ttd, now);
    if (remaining < 2.0) remaining = 2.0;
    if (remaining > 3600.0) remaining = 3600.0;
    *effective_ttl_out = (uint32_t)remaining;
    return true;
}

STATIC_TEST bool append_glue_records(zone_arena_t *current_zone, const char *target,
                                     const char *zone_apex, uint8_t *res,
                                     size_t max_res_len, uint16_t *offset,
                                     compress_ctx_t *comp_ctx, uint16_t *arcount,
                                     const char client_loc[2],
                                     const char *client_ecs_tag,
                                     const char *client_loc_tag,
                                     additional_from_auth_t policy,
                                     view_snapshot_t *view) {

  if (!current_zone || !target || policy == ADDITIONAL_AUTH_NO) return true;

  // 1. Fast path: check prelinked glue
  if (current_zone->prelinked_glue && current_zone->prelinked_glue_count > 0) {
    for (int e = 0; e < current_zone->prelinked_glue_count; e++) {
      prelinked_glue_entry_t *entry = &current_zone->prelinked_glue[e];
      if (entry->target_name && domain_names_match_ci(entry->target_name, target)) {
        time_t tinydns_now = current_zone->is_tinydns_format ? time(NULL) : 0;
        for (int r = 0; r < entry->record_count; r++) {
          dns_record_t *rec = entry->records[r];
          if (!rec) continue;
          uint32_t eff_ttl;
          if (!tinydns_record_currently_valid(rec, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &eff_ttl)) continue;
          dns_record_t rec_copy = *rec;
          rec_copy.ttl_value = eff_ttl;
          uint16_t saved_offset = *offset;
          if (serialize_dns_record(res, max_res_len, offset,
                                   &rec_copy, comp_ctx,
                                   NULL, 0xFFFFFFFF) < 0) {
            *offset = saved_offset;
            return false;
          } else {
            (*arcount)++;
          }
        }
        return true;
      }
    }
  }

  // 2. In-zone search (covers in-domain glue and out-of-zone glue in current_zone)
  size_t t_len = strlen(target), a_len = strlen(zone_apex);
  while (t_len > 0 && target[t_len - 1] == '.') t_len--;
  while (a_len > 0 && zone_apex[a_len - 1] == '.') a_len--;

  bool is_in_domain = (t_len >= a_len &&
                       strncasecmp(target + (t_len - a_len), zone_apex, a_len) == 0 &&
                       (t_len == a_len || target[t_len - a_len - 1] == '.'));

  if (policy == ADDITIONAL_AUTH_IN_DOMAIN && !is_in_domain) {
    return true;
  }

  bool in_zone_found = false;
  if (current_zone->hash_size > 0 && current_zone->hash_table) {
    time_t tinydns_now = (current_zone && current_zone->is_tinydns_format) ? time(NULL) : 0;
    uint32_t hashes[2];
    int h_count = 1;
    hashes[0] = calc_fnv1a_str(target);
    char alt_tgt[256];
    size_t raw_len = strlen(target);
    if (raw_len > 0 && target[raw_len - 1] == '.') {
      snprintf(alt_tgt, sizeof(alt_tgt), "%.*s", (int)(raw_len - 1), target);
      hashes[1] = calc_fnv1a_str(alt_tgt);
      h_count = 2;
    } else if (raw_len > 0 && raw_len + 1 < sizeof(alt_tgt)) {
      snprintf(alt_tgt, sizeof(alt_tgt), "%s.", target);
      hashes[1] = calc_fnv1a_str(alt_tgt);
      h_count = 2;
    }

    dns_record_t *added_recs[32];
    int added_count = 0;

    for (int h = 0; h < h_count; h++) {
      size_t idx = hashes[h] & (current_zone->hash_size - 1);
      if (h == 1 && idx == (hashes[0] & (current_zone->hash_size - 1))) continue;
      for (int j = current_zone->hash_table[idx]; j != -1;
           j = current_zone->records[j].next_record) {
        dns_record_t *rec = &current_zone->records[j];
        if ((rec->type_code == 1 || rec->type_code == 28) &&
            domain_names_match_ci(rec->name, target)) {
          bool dup = false;
          for (int a = 0; a < added_count; a++) {
            if (added_recs[a] == rec) { dup = true; break; }
          }
          if (dup) continue;
          if (added_count < 32) added_recs[added_count++] = rec;

          uint32_t eff_ttl;
          if (!tinydns_record_currently_valid(rec, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &eff_ttl)) continue;
          dns_record_t rec_copy = *rec;
          rec_copy.ttl_value = eff_ttl;
          uint16_t saved_offset = *offset;
          if (serialize_dns_record(res, max_res_len, offset,
                                   &rec_copy, comp_ctx,
                                   NULL, 0xFFFFFFFF) < 0) {
            *offset = saved_offset;
            return false;
          } else {
            (*arcount)++;
            in_zone_found = true;
          }
        }
      }
    }
  }

  if (in_zone_found) {
    return true;
  }

  // 3. Fallback: Search sibling authoritative zones in view dynamically if policy == ADDITIONAL_AUTH_YES
  if (policy == ADDITIONAL_AUTH_YES && view) {
    zone_db_entry_t *sib_entry = find_zone_in_view(view, target);
    if (sib_entry) {
      zone_arena_t *sib_arena = atomic_load_explicit(&sib_entry->rcu.active, memory_order_acquire);
      if (sib_arena && sib_arena != current_zone && sib_arena->hash_size > 0 && sib_arena->hash_table) {
        time_t tinydns_now = sib_arena->is_tinydns_format ? time(NULL) : 0;
        uint32_t hashes[2];
        int h_count = 1;
        hashes[0] = calc_fnv1a_str(target);
        char alt_tgt[256];
        size_t raw_len = strlen(target);
        if (raw_len > 0 && target[raw_len - 1] == '.') {
          snprintf(alt_tgt, sizeof(alt_tgt), "%.*s", (int)(raw_len - 1), target);
          hashes[1] = calc_fnv1a_str(alt_tgt);
          h_count = 2;
        } else if (raw_len > 0 && raw_len + 1 < sizeof(alt_tgt)) {
          snprintf(alt_tgt, sizeof(alt_tgt), "%s.", target);
          hashes[1] = calc_fnv1a_str(alt_tgt);
          h_count = 2;
        }

        dns_record_t *added_recs[32];
        int added_count = 0;

        for (int h = 0; h < h_count; h++) {
          size_t idx = hashes[h] & (sib_arena->hash_size - 1);
          if (h == 1 && idx == (hashes[0] & (sib_arena->hash_size - 1))) continue;
          for (int j = sib_arena->hash_table[idx]; j != -1;
               j = sib_arena->records[j].next_record) {
            dns_record_t *rec = &sib_arena->records[j];
            if ((rec->type_code == 1 || rec->type_code == 28) &&
                domain_names_match_ci(rec->name, target)) {
              bool dup = false;
              for (int a = 0; a < added_count; a++) {
                if (added_recs[a] == rec) { dup = true; break; }
              }
              if (dup) continue;
              if (added_count < 32) added_recs[added_count++] = rec;

              uint32_t eff_ttl;
              if (!tinydns_record_currently_valid(rec, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &eff_ttl)) continue;
              dns_record_t rec_copy = *rec;
              rec_copy.ttl_value = eff_ttl;
              uint16_t saved_offset = *offset;
              if (serialize_dns_record(res, max_res_len, offset,
                                       &rec_copy, comp_ctx,
                                       NULL, 0xFFFFFFFF) < 0) {
                *offset = saved_offset;
                return false;
              } else {
                (*arcount)++;
              }
            }
          }
        }
      }
    }
  }

  return true;
}

STATIC_TEST void collect_additional_rr_glue(dns_record_t *rec,
                                       const char *glue_targets[16],
                                       int *glue_target_count,
                                       bool minimal_responses) {
  if (minimal_responses || !rec || !glue_targets || !glue_target_count) return;
  const char *target = NULL;
  if (rec->type_code == 15 && rec->rdata_count >= 2) {
    // MX: rdata[0] = preference, rdata[1] = exchange (RFC 1035 §3.3.9)
    target = rec->rdata[1];
  } else if (rec->type_code == 33 && rec->rdata_count >= 4) {
    // SRV: rdata[0] = priority, rdata[1] = weight, rdata[2] = port, rdata[3] = target (RFC 2782)
    target = rec->rdata[3];
  } else if (rec->type_code == 2 && rec->rdata_count >= 1) {
    // NS: rdata[0] = target
    target = rec->rdata[0];
  }
  if (!target || *target == '\0') return;

  for (int k = 0; k < *glue_target_count; k++) {
    if (glue_targets[k] && strcasecmp(glue_targets[k], target) == 0) {
      return;
    }
  }
  if (*glue_target_count < 16) {
    glue_targets[(*glue_target_count)++] = target;
  }
}

STATIC_TEST bool nsec_covers_name(const dns_record_t *rec, const char *name) {
  if (!rec || rec->type_code != 47 || rec->rdata_count < 1 || !rec->rdata[0] ||
      !rec->name || !name)
    return false;
  const char *owner = rec->name;
  const char *next = rec->rdata[0];
  int cmp_wrap = compare_canonical_name(owner, next);
  if (cmp_wrap < 0) {
    return (compare_canonical_name(owner, name) <= 0 &&
            compare_canonical_name(name, next) < 0);
  } else {
    return (compare_canonical_name(owner, name) <= 0 ||
            compare_canonical_name(name, next) < 0);
  }
}

STATIC_TEST dns_record_t *find_covering_nsec(zone_arena_t *zone, const char *name) {
  if (!zone || !name) return NULL;
  if (zone->nsec_records && zone->nsec_count > 0) {
    int low = 0, high = (int)zone->nsec_count - 1;
    int best = -1;
    while (low <= high) {
      int mid = low + (high - low) / 2;
      int cmp = compare_canonical_name(zone->nsec_records[mid]->name, name);
      if (cmp <= 0) {
        best = mid;
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }
    if (best >= 0) {
      dns_record_t *rec = zone->nsec_records[best];
      if (nsec_covers_name(rec, name))
        return rec;
    } else {
      // name is strictly smaller than first NSEC owner, check last NSEC (wrap-around)
      dns_record_t *rec = zone->nsec_records[zone->nsec_count - 1];
      if (nsec_covers_name(rec, name))
        return rec;
    }
    return NULL;
  }

  // Linear scan fallback
  for (size_t i = 0; i < zone->count; i++) {
    dns_record_t *rec = &zone->records[i];
    if (rec->type_code == 47 && nsec_covers_name(rec, name))
      return rec;
  }
  return NULL;
}

STATIC_TEST bool name_exists_in_zone(zone_arena_t *zone, const char *name, const char client_loc[2], const char *client_ecs_tag, const char *client_loc_tag) {
  if (!zone || !name || !zone->hash_table || zone->hash_size == 0) return false;
  size_t name_len = strlen(name);
  time_t tinydns_now = (zone && zone->is_tinydns_format) ? time(NULL) : 0;

  // (a) Exact match check via hash table
  uint32_t h = calc_fnv1a_str(name);
  size_t idx = h & (zone->hash_size - 1);
  for (int i = zone->hash_table[idx]; i != -1; i = zone->records[i].next_record) {
    dns_record_t *rec = &zone->records[i];
    if (strcasecmp(rec->name, name) == 0) {
      uint32_t eff_ttl;
      if (tinydns_record_currently_valid(rec, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &eff_ttl)) return true;
    }
  }

  // (b) Empty Non-Terminal (ENT) check via binary search on sorted_unique_names
  if (!zone->sorted_unique_names || zone->sorted_unique_count == 0) return false;

  int lo = 0, hi = (int)zone->sorted_unique_count - 1;
  int pos = (int)zone->sorted_unique_count;
  while (lo <= hi) {
    int mid = lo + (hi - lo) / 2;
    if (compare_canonical_name(zone->sorted_unique_names[mid], name) > 0) {
      pos = mid;
      hi = mid - 1;
    } else {
      lo = mid + 1;
    }
  }

  if (pos >= (int)zone->sorted_unique_count) return false;

  const char *rn = zone->sorted_unique_names[pos];
  size_t rn_len = strlen(rn);
  if (rn_len > name_len &&
      rn[rn_len - name_len - 1] == '.' &&
      strcasecmp(rn + rn_len - name_len, name) == 0) {
    return true;
  }
  return false;
}

STATIC_TEST const char *find_closest_encloser(zone_arena_t *zone, const char *qname, const char *zone_apex, const char client_loc[2], const char *client_ecs_tag, const char *client_loc_tag) {
  if (!zone || !qname || !zone_apex || !zone->hash_table || zone->hash_size == 0)
    return zone_apex;
  const char *parent = qname;
  size_t apex_len = strlen(zone_apex);
  while ((parent = strchr_unescaped(parent, '.')) != NULL) {
    parent++;
    if (*parent == '\0') break;

    size_t p_len = strlen(parent);
    if (p_len < apex_len) break;
    if (strcasecmp(parent, zone_apex) == 0)
      return zone_apex;
    if (p_len > apex_len) {
      if (parent[p_len - apex_len - 1] != '.' ||
          strcasecmp(parent + p_len - apex_len, zone_apex) != 0) {
        break; // Outside zone apex
      }
    }

    if (name_exists_in_zone(zone, parent, client_loc, client_ecs_tag, client_loc_tag)) {
      return parent;
    }
  }
  return zone_apex;
}


static void base32hex_encode(const uint8_t *data, size_t len, char *out, size_t out_cap) {
    if (!out || out_cap == 0) return;
    static const char alphabet[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
    size_t out_len = 0;
    uint32_t buffer = 0;
    int bits_left = 0;
    for (size_t i = 0; i < len; i++) {
        buffer = (buffer << 8) | data[i];
        bits_left += 8;
        while (bits_left >= 5) {
            if (out_len + 1 >= out_cap) { out[out_len] = '\0'; return; }
            out[out_len++] = alphabet[(buffer >> (bits_left - 5)) & 0x1F];
            bits_left -= 5;
        }
    }
    if (bits_left > 0 && out_len + 1 < out_cap) {
        out[out_len++] = alphabet[(buffer << (5 - bits_left)) & 0x1F];
    }
    out[out_len] = '\0';
}

STATIC_TEST size_t hex_to_bytes(const char *hex, uint8_t *out, size_t max_out) {
    if (!hex || strcmp(hex, "-") == 0 || strcmp(hex, "") == 0) return 0;
    size_t hlen = strlen(hex);
    size_t count = 0;
    for (size_t i = 0; i + 1 < hlen && count < max_out; i += 2) {
        char byte_str[3] = { hex[i], hex[i+1], '\0' };
        out[count++] = (uint8_t)strtoul(byte_str, NULL, 16);
    }
    return count;
}

STATIC_TEST size_t name_to_canonical_wire(const char *name, uint8_t *wire, size_t max_wire) {
    if (!name || max_wire < 1) return 0;
    size_t pos = 0;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t label_len = dot ? (size_t)(dot - p) : strlen(p);
        if (label_len == 0) break;
        if (label_len > 63 || pos + 1 + label_len >= max_wire) return 0;
        wire[pos++] = (uint8_t)label_len;
        for (size_t i = 0; i < label_len; i++) {
            char c = p[i];
            if (c >= 'A' && c <= 'Z') c += 32;
            wire[pos++] = (uint8_t)c;
        }
        if (!dot) break;
        p = dot + 1;
    }
    if (pos >= max_wire) return 0;
    wire[pos++] = 0; // Root label
    return pos;
}

STATIC_TEST bool compute_nsec3_hash(const char *name, uint8_t algo, uint16_t iterations,
                               const uint8_t *salt, size_t salt_len,
                               char *out_b32, size_t out_b32_sz) {
    if (algo != 1) return false;
    uint8_t wire[256];
    size_t wire_len = name_to_canonical_wire(name, wire, sizeof(wire));
    if (wire_len == 0) return false;

    uint8_t digest[20];
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, wire, wire_len);
    if (salt_len > 0) SHA1_Update(&ctx, salt, salt_len);
    SHA1_Final(digest, &ctx);

    for (uint16_t i = 0; i < iterations; i++) {
        SHA1_Init(&ctx);
        SHA1_Update(&ctx, digest, 20);
        if (salt_len > 0) SHA1_Update(&ctx, salt, salt_len);
        SHA1_Final(digest, &ctx);
    }
    base32hex_encode(digest, 20, out_b32, out_b32_sz);
    return true;
}

STATIC_TEST bool nsec3_covers_hash(const char *owner_hash, const char *next_hash, const char *target_hash) {
    if (!owner_hash || !next_hash || !target_hash) return false;
    int cmp_owner_next = strcasecmp(owner_hash, next_hash);
    int cmp_owner_tgt = strcasecmp(owner_hash, target_hash);
    int cmp_tgt_next = strcasecmp(target_hash, next_hash);

    if (cmp_owner_next < 0) {
        return (cmp_owner_tgt < 0 && cmp_tgt_next < 0);
    } else if (cmp_owner_next > 0) {
        return (cmp_owner_tgt < 0 || cmp_tgt_next < 0);
    } else {
        return (cmp_owner_tgt != 0);
    }
}

STATIC_TEST dns_record_t *find_matching_nsec3(zone_arena_t *zone, const char *hash_b32, const char *apex) {
    if (!zone || !hash_b32 || !apex || !zone->hash_table || zone->hash_size == 0) return NULL;
    char owner_name[300];
    snprintf(owner_name, sizeof(owner_name), "%s.%s", hash_b32, apex);
    uint32_t h = calc_fnv1a_str(owner_name);
    size_t idx = h & (zone->hash_size - 1);
    for (int i = zone->hash_table[idx]; i != -1; i = zone->records[i].next_record) {
        dns_record_t *rec = &zone->records[i];
        if (rec->type_code == 50 && domain_names_match_ci(rec->name, owner_name)) {
            return rec;
        }
    }
    return NULL;
}

STATIC_TEST dns_record_t *find_covering_nsec3(zone_arena_t *zone, const char *target_hash) {
    if (!zone || !target_hash || !zone->records || zone->count == 0) return NULL;
    for (size_t i = 0; i < zone->count; i++) {
        dns_record_t *rec = &zone->records[i];
        if (rec->type_code == 50 && rec->name && rec->rdata_count >= 5 && rec->rdata[4]) {
            char owner_hash[64] = {0};
            const char *dot = strchr(rec->name, '.');
            if (!dot || dot <= rec->name) continue;
            size_t hlen = (size_t)(dot - rec->name);
            if (hlen >= sizeof(owner_hash)) continue;
            memcpy(owner_hash, rec->name, hlen);
            owner_hash[hlen] = '\0';
            if (nsec3_covers_hash(owner_hash, rec->rdata[4], target_hash)) {
                return rec;
            }
        }
    }
    return NULL;
}

STATIC_TEST bool find_next_closer_name(const char *qname, const char *encloser, char *out, size_t out_sz) {
    if (!qname || !encloser || !out || out_sz == 0) return false;
    size_t qlen = strlen(qname);
    size_t elen = strlen(encloser);
    while (qlen > 0 && qname[qlen - 1] == '.') qlen--;
    while (elen > 0 && encloser[elen - 1] == '.') elen--;
    if (qlen <= elen) return false;
    if (strncasecmp(qname + qlen - elen, encloser, elen) != 0) return false;
    if (qname[qlen - elen - 1] != '.') return false;
    /* [C-3] qlen - elen - 2 がアンダーフローする条件を除外する。
     * next-closer name が存在するには qname は encloser より少なくとも
     * "X." (2文字) 長い必要がある。*/
    if (qlen < elen + 2) return false;

    const char *p = qname + qlen - elen - 2;
    while (p >= qname && *p != '.') p--;
    const char *start = p + 1;
    size_t nc_len = (qname + qlen) - start;
    if (nc_len + 1 >= out_sz) return false;
    memcpy(out, start, nc_len);
    out[nc_len] = '\0';
    return true;
}

STATIC_TEST bool attach_nsec3_record(zone_arena_t *zone, dns_record_t *rec,
                                uint8_t *res, size_t max_res_len, uint16_t *offset,
                                compress_ctx_t *comp_ctx, uint16_t *nscount,
                                dns_record_t **attached, int *attached_count) {
    if (!rec) return true;
    for (int i = 0; i < *attached_count; i++) {
        if (attached[i] == rec) return true;
    }
    if (*attached_count < 8) attached[(*attached_count)++] = rec;

    if (serialize_dns_record(res, max_res_len, offset, rec, comp_ctx, NULL, 0xFFFFFFFF) < 0) {
        return false;
    }
    (*nscount)++;
    uint32_t c_hash = calc_fnv1a_str(rec->name);
    size_t c_idx = c_hash & (zone->hash_size - 1);
    return attach_covering_rrsig(zone, c_idx, rec->name, NULL, 50,
                                 res, max_res_len, offset, comp_ctx, nscount);
}

STATIC_TEST bool find_delegation(zone_arena_t *current_zone, const char *qname,
                            uint32_t qname_hash,
                            const char *zone_apex, uint8_t *res,
                            size_t max_res_len, uint16_t *offset,
                            compress_ctx_t *comp_ctx, uint16_t *nscount,
                            uint16_t *arcount, bool is_ds_query,
                            const char client_loc[2],
                            const char *client_ecs_tag,
                            const char *client_loc_tag,
                            additional_from_auth_t policy,
                            view_snapshot_t *view,
                            bool dnssec_ok) {
  if (!current_zone || current_zone->hash_size == 0 ||
      !current_zone->hash_table)
    return false;
  time_t tinydns_now = (current_zone && current_zone->is_tinydns_format) ? time(NULL) : 0;
  const char *name = qname;
  while (name && *name && !domain_names_match_ci(name, zone_apex)) {
    // RFC 4035 §3.1.4.1: 委任点そのもの(name == qname)へのDSクエリは、
    // 参照応答(referral)にせず、権威応答としてフェーズ2の通常検索へ継続させる。
    if (is_ds_query && name == qname) {
      name = strchr_unescaped(name, '.');
      if (name)
        name++;
      continue;
    }
    uint32_t hash = (name == qname) ? qname_hash : calc_fnv1a_str(name);
    size_t idx = hash & (current_zone->hash_size - 1);
    bool delegated = false;
    for (int i = current_zone->hash_table[idx]; i != -1;
         i = current_zone->records[i].next_record) {
      dns_record_t *rec = &current_zone->records[i];
      if (rec->type_code == 2 &&
          domain_names_match_ci(rec->name, name)) {
        uint32_t eff_ttl;
        if (!tinydns_record_currently_valid(rec, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &eff_ttl)) continue;
        delegated = true;
        dns_record_t rec_copy = *rec;
        rec_copy.ttl_value = eff_ttl;
        if (serialize_dns_record(res, max_res_len, offset,
                                 &rec_copy, comp_ctx, NULL,
                                 0xFFFFFFFF) < 0) {
          res[2] |= 0x02;
          return true;
        } else
          (*nscount)++;
      }
    }
    if (delegated) {
      res[2] &= ~0x04; // Clear AA (Referral response MUST NOT have AA set)

      // DNSSEC delegation handling (RFC 4035 §3.1.4 / RFC 5155 §7.2.3)
      if (dnssec_ok) {
        bool has_ds = false;
        for (int i = current_zone->hash_table[idx]; i != -1;
             i = current_zone->records[i].next_record) {
          dns_record_t *rec = &current_zone->records[i];
          if (rec->type_code == 43 /* DS */ && strcasecmp(rec->name, name) == 0) {
            uint32_t eff_ttl;
            if (!tinydns_record_currently_valid(rec, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &eff_ttl)) continue;
            has_ds = true;
            dns_record_t rec_copy = *rec;
            rec_copy.ttl_value = eff_ttl;
            if (serialize_dns_record(res, max_res_len, offset, &rec_copy, comp_ctx, NULL, 0xFFFFFFFF) < 0) {
              res[2] |= 0x02;
              return true;
            }
            (*nscount)++;
          }
        }
        if (has_ds) {
          if (!attach_covering_rrsig(current_zone, idx, name, NULL, 43,
                                     res, max_res_len, offset, comp_ctx, nscount)) {
            res[2] |= 0x02;
            return true;
          }
        } else {
          // Insecure Delegation: Prove non-existence of DS (RFC 4035 §3.1.4 / RFC 5155 §7.2.3)
          if (!zone_uses_nsec3(current_zone, zone_apex)) {
            bool nsec_added = false;
            for (int i = current_zone->hash_table[idx]; i != -1;
                 i = current_zone->records[i].next_record) {
              dns_record_t *rec = &current_zone->records[i];
              if (rec->type_code == 47 /* NSEC */ && strcasecmp(rec->name, name) == 0) {
                if (rec->rdata_count < 1) break;
                uint32_t eff_ttl;
                if (!tinydns_record_currently_valid(rec, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &eff_ttl)) continue;
                dns_record_t rec_copy = *rec;
                rec_copy.ttl_value = eff_ttl;
                if (serialize_dns_record(res, max_res_len, offset, &rec_copy, comp_ctx, NULL, 0xFFFFFFFF) < 0) {
                  res[2] |= 0x02;
                  return true;
                }
                (*nscount)++;
                if (!attach_covering_rrsig(current_zone, idx, name, NULL, 47,
                                           res, max_res_len, offset, comp_ctx, nscount)) {
                  res[2] |= 0x02;
                  return true;
                }
                nsec_added = true;
                break;
              }
            }
            if (!nsec_added) {
              dns_record_t *cover = find_covering_nsec(current_zone, name);
              if (cover) {
                if (serialize_dns_record(res, max_res_len, offset, cover, comp_ctx, NULL, 0xFFFFFFFF) < 0) {
                  res[2] |= 0x02;
                  return true;
                }
                (*nscount)++;
                uint32_t c_hash = calc_fnv1a_str(cover->name);
                size_t c_idx = c_hash & (current_zone->hash_size - 1);
                if (!attach_covering_rrsig(current_zone, c_idx, cover->name, NULL, 47,
                                           res, max_res_len, offset, comp_ctx, nscount)) {
                  res[2] |= 0x02;
                  return true;
                }
              }
            }
          } else {
            // NSEC3 Insecure Delegation Proof (RFC 5155 §7.2.3)
            uint32_t a_hash = calc_fnv1a_str(zone_apex);
            size_t a_idx = a_hash & (current_zone->hash_size - 1);
            dns_record_t *param_rec = NULL;
            for (int i = current_zone->hash_table[a_idx]; i != -1; i = current_zone->records[i].next_record) {
              if (current_zone->records[i].type_code == 51 &&
                  domain_names_match_ci(current_zone->records[i].name, zone_apex)) {
                param_rec = &current_zone->records[i];
                break;
              }
            }
            if (param_rec && param_rec->rdata_count >= 4) {
              uint8_t algo = (uint8_t)atoi(param_rec->rdata[0]);
              uint16_t iterations = (uint16_t)atoi(param_rec->rdata[2]);
              uint8_t salt[64];
              size_t salt_len = hex_to_bytes(param_rec->rdata[3], salt, sizeof(salt));
              dns_record_t *attached_nsec3[8];
              int attached_nsec3_cnt = 0;

              char q_hash[64];
              if (compute_nsec3_hash(name, algo, iterations, salt, salt_len, q_hash, sizeof(q_hash))) {
                dns_record_t *m_rec = find_matching_nsec3(current_zone, q_hash, zone_apex);
                if (m_rec) {
                  if (!attach_nsec3_record(current_zone, m_rec, res, max_res_len, offset, comp_ctx, nscount, attached_nsec3, &attached_nsec3_cnt)) {
                    res[2] |= 0x02;
                    return true;
                  }
                } else {
                  // Opt-Out: Next Closer covering NSEC3 and Closest Provable Encloser matching NSEC3 (RFC 5155 §7.2.3)
                  dns_record_t *c_rec = find_covering_nsec3(current_zone, q_hash);
                  if (c_rec) {
                    if (!attach_nsec3_record(current_zone, c_rec, res, max_res_len, offset, comp_ctx, nscount, attached_nsec3, &attached_nsec3_cnt)) {
                      res[2] |= 0x02;
                      return true;
                    }
                  }
                  const char *encloser = find_closest_encloser(current_zone, name, zone_apex, client_loc, client_ecs_tag, client_loc_tag);
                  if (encloser) {
                    char ce_hash[64];
                    if (compute_nsec3_hash(encloser, algo, iterations, salt, salt_len, ce_hash, sizeof(ce_hash))) {
                      dns_record_t *ce_rec = find_matching_nsec3(current_zone, ce_hash, zone_apex);
                      if (ce_rec) {
                        if (!attach_nsec3_record(current_zone, ce_rec, res, max_res_len, offset, comp_ctx, nscount, attached_nsec3, &attached_nsec3_cnt)) {
                          res[2] |= 0x02;
                          return true;
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }

      for (int i = current_zone->hash_table[idx]; i != -1;
           i = current_zone->records[i].next_record) {
        if (current_zone->records[i].type_code == 2 &&
            strcasecmp(current_zone->records[i].name, name) == 0 &&
            current_zone->records[i].rdata_count > 0) {
          const char *target = current_zone->records[i].rdata[0];
          if (!append_glue_records(current_zone, target, zone_apex, res,
                                   max_res_len, offset, comp_ctx, arcount, client_loc, client_ecs_tag, client_loc_tag, policy, view)) {
            res[2] |= 0x02;
            return true;
          }
        }
      }
      return true;
    }
    name = strchr_unescaped(name, '.');
    if (name)
      name++;
  }
  return false;
}

void resolve_name(const char *qname, uint16_t qclass, const uint16_t *qtypes, int num_qtypes,
                         zone_db_entry_t **db_entry_ptr,
                         zone_arena_t **current_zone_ptr, uint8_t *res,
                         size_t max_res_len, uint16_t *offset,
                         compress_ctx_t *comp_ctx, uint16_t *ancount,
                         uint16_t *nscount, uint16_t *arcount,
                         bool minimal_responses,
                         bool minimal_any, uint32_t minimal_any_ttl, bool dnssec_ok,
                         view_snapshot_t *view, uint32_t *qtx_included_out,
                         const char *client_ip, server_config_t *cfg,
                         bool ecs_trusted, const uint8_t *ecs_addr, uint16_t ecs_family,
                         uint8_t ecs_source_prefix,
                         uint8_t *out_ecs_scope_prefix) {
  if (out_ecs_scope_prefix) *out_ecs_scope_prefix = 0;
  if (qtx_included_out) *qtx_included_out = 0;
  uint16_t initial_offset = *offset;
  uint16_t initial_ancount = *ancount;
  uint16_t initial_nscount = *nscount;
  uint16_t initial_arcount = *arcount;
  uint8_t temp_scope_prefix = 0;
  bool ecs_used = false;
  char current_qname[256];
  strlcpy(current_qname, qname, sizeof(current_qname));
  size_t current_qname_len = strlen(current_qname);
  uint32_t current_qname_hash = calc_fnv1a_str(current_qname);
  char visited_qnames[16][256];
  int visited_count = 0;
  strlcpy(visited_qnames[visited_count++], current_qname, sizeof(visited_qnames[0]));
  const char *glue_targets[16];
  int glue_target_count = 0;
  memset(glue_targets, 0, sizeof(glue_targets));
  bool chain_exhausted = true;
  bool any_cname_wc_expanded = false;
  char first_wc_qname[256] = {0};
  zone_arena_t *first_wc_zone = NULL;
  char first_wc_apex[256] = {0};
  for (int depth = 0; depth < 16; depth++) {
    zone_db_entry_t *db_entry = *db_entry_ptr;
    zone_arena_t *current_zone = *current_zone_ptr;
    if (!current_zone || current_zone->hash_size == 0 ||
        !current_zone->hash_table) {
      res[3] = (res[3] & 0xF0) | 0x02; // SERVFAIL
      *offset = initial_offset;
      *ancount = initial_ancount;
      *nscount = initial_nscount;
      *arcount = initial_arcount;
      if (out_ecs_scope_prefix) *out_ecs_scope_prefix = 0;
      return;
    }

    uint32_t apex_hash = 0;
    size_t apex_idx = 0;
    bool apex_hash_computed = false;

    time_t tinydns_now = 0;
    if (current_zone->is_tinydns_format) {
      tinydns_now = time(NULL);
    }
    char client_loc[2] = {0, 0};
    tinydns_resolve_client_location(current_zone, client_ip, client_loc);

    zone_config_t *zcfg = (cfg && db_entry) ? find_zone_config_in_view(cfg, db_entry->view_name, db_entry->domain) : NULL;
    const char *client_loc_tag = resolve_bind_location_tag(current_zone, cfg, zcfg, client_ip);
    const char *client_ecs_tag = NULL;
    if (ecs_trusted && ecs_addr) {
      uint8_t cur_scope = 0;
      client_ecs_tag = resolve_ecs_subnet_tag(current_zone, cfg, zcfg, ecs_addr, ecs_family, &cur_scope);
      if (cur_scope > ecs_source_prefix) {
        cur_scope = ecs_source_prefix;
      }
      if (cur_scope > temp_scope_prefix) temp_scope_prefix = cur_scope;
    }
    
    // ==== フェーズ1: 委任判定 ====
    additional_from_auth_t policy = (zcfg && zcfg->additional_from_auth_specified)
                                        ? zcfg->additional_from_auth
                                        : (cfg ? cfg->additional_from_auth : ADDITIONAL_AUTH_YES);
    bool is_ds_query = (num_qtypes > 0 && qtypes[0] == 43);
    if (find_delegation(current_zone, current_qname, current_qname_hash, db_entry->domain, res,
                        max_res_len, offset, comp_ctx, nscount, arcount, is_ds_query, client_loc, client_ecs_tag, client_loc_tag, policy, view, dnssec_ok)) {
      return;
    }
      
    // ==== フェーズ2: QNAME完全一致検索 ====
    bool found = false, type_matched = false, cname_followed = false, wc_found = false;
    uint32_t hash = current_qname_hash;
    size_t idx = hash & (current_zone->hash_size - 1);
    uint16_t signed_types[64];
    int signed_types_count = 0;
    bool has_any = (qtypes[0] == 255);
    bool skip_synthesis = false;
    if (has_any && minimal_any) {
      bool name_exists = false, has_cname = false, has_rrsig = false;
      for (int i = current_zone->hash_table[idx]; i != -1;
           i = current_zone->records[i].next_record) {
        dns_record_t *rec = &current_zone->records[i];
        if (strcasecmp(rec->name, current_qname) == 0) {
          uint32_t eff_ttl;
          if (!tinydns_record_currently_valid(rec, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &eff_ttl)) continue;
          name_exists = true;
          if (rec->type_code == 5) has_cname = true;   // CNAME
          if (rec->type_code == 46) has_rrsig = true;  // RRSIG
        }
      }
      skip_synthesis = dnssec_ok && has_rrsig;
      if (name_exists && !has_cname && !skip_synthesis) {
        dns_record_t hinfo_rec;
        memset(&hinfo_rec, 0, sizeof(hinfo_rec));
        hinfo_rec.name = (char *)current_qname;
        hinfo_rec.type_code = 13; // HINFO
        char ttl_str[32];
        snprintf(ttl_str, sizeof(ttl_str), "%u", minimal_any_ttl);
        hinfo_rec.ttl = ttl_str;
        hinfo_rec.rdata[0] = "RFC8482";
        hinfo_rec.rdata[1] = "";
        hinfo_rec.rdata_count = 2;
        if (serialize_dns_record(res, max_res_len, offset, &hinfo_rec, comp_ctx,
                                 NULL, 0xFFFFFFFF) < 0) {
          res[2] |= 0x02;
          return;
        }
        (*ancount)++;
        found = true;
        chain_exhausted = false;
        break;
      }
    }

    uint16_t minimal_any_chosen_type = 0;
    for (int i = current_zone->hash_table[idx]; i != -1;
         i = current_zone->records[i].next_record) {
      dns_record_t *rec = &current_zone->records[i];
      if (strcasecmp(rec->name, current_qname) == 0) {
        uint16_t r_class = rec->class_val ? rec->class_val : 1;
        bool class_matches = (qclass == 255 || qclass == r_class);
        if (!class_matches) continue;
        uint32_t eff_ttl;
        if (!tinydns_record_currently_valid(rec, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &eff_ttl)) continue;
        found = true;
        uint16_t rec_type = rec->type_code;
        bool follow_cname = false;
        if (rec_type == 5) {
          if (qtypes[0] != 5 && qtypes[0] != 255) { follow_cname = true; }
        }
        dns_record_t rec_copy = *rec;
        rec_copy.ttl_value = eff_ttl;
        if (follow_cname) {
          if (rec->ecs_subnet_tag != NULL) ecs_used = true;
          if (serialize_dns_record(res, max_res_len, offset, &rec_copy, comp_ctx,
                                   NULL, 0xFFFFFFFF) < 0) {
            res[2] |= 0x02;
            if (ecs_used && out_ecs_scope_prefix) *out_ecs_scope_prefix = temp_scope_prefix;
            return;
          } else
            (*ancount)++;
          if (dnssec_ok) {
            if (!attach_covering_rrsig(current_zone, idx, current_qname, NULL, 5,
                                      res, max_res_len, offset, comp_ctx, ancount)) {
              res[2] |= 0x02;
              if (ecs_used && out_ecs_scope_prefix) *out_ecs_scope_prefix = temp_scope_prefix;
              return;
            }
          }
          if (rec->rdata_count > 0) {
            const char *target = rec->rdata[0];
            bool loop_detected = false;
            for (int v = 0; v < visited_count; v++) {
              if (domain_names_match_ci(target, visited_qnames[v])) {
                loop_detected = true;
                break;
              }
            }
            if (loop_detected) {
              res[3] &= 0xF0;
              if (ecs_used && out_ecs_scope_prefix) *out_ecs_scope_prefix = temp_scope_prefix;
              return;
            }
            if (visited_count < 16) {
              strlcpy(visited_qnames[visited_count++], target, sizeof(visited_qnames[0]));
            }
            strlcpy(current_qname, target, sizeof(current_qname));
            current_qname_len = strlen(current_qname);
            current_qname_hash = calc_fnv1a_str(current_qname);
            cname_followed = true;
          }
          break;
        } else {
          /* [RFC 8482 §4.2] DNSSECゾーンでのANYクエリ: 最初に見つかった1つのRRsetのみを返し、他は展開しない */
          if (has_any && minimal_any && skip_synthesis) {
            if (rec_type != 46) {
              if (minimal_any_chosen_type == 0) {
                minimal_any_chosen_type = rec_type;
              } else if (minimal_any_chosen_type != rec_type) {
                continue;
              }
            } else {
              continue;
            }
          }
          if (qtypes[0] == 255 || qtypes[0] == rec_type) {
            type_matched = true;
            if (rec->ecs_subnet_tag != NULL) ecs_used = true;
            if (serialize_dns_record(res, max_res_len, offset, &rec_copy, comp_ctx,
                                     NULL, 0xFFFFFFFF) < 0) {
              res[2] |= 0x02;
              if (ecs_used && out_ecs_scope_prefix) *out_ecs_scope_prefix = temp_scope_prefix;
              return;
            }
            (*ancount)++;
            collect_additional_rr_glue(&rec_copy, glue_targets, &glue_target_count, minimal_responses);
            if (dnssec_ok && rec_type != 46) {
              bool already_signed = false;
              for (int s = 0; s < signed_types_count; s++) {
                if (signed_types[s] == rec_type) {
                  already_signed = true;
                  break;
                }
              }
              if (!already_signed) {
                if (signed_types_count < (int)(sizeof(signed_types) / sizeof(signed_types[0]))) {
                  signed_types[signed_types_count++] = rec_type;
                }
                if (!attach_covering_rrsig(current_zone, idx, current_qname, NULL, rec_type,
                                          res, max_res_len, offset, comp_ctx, ancount)) {
                  res[2] |= 0x02;
                  return;
                }
              }
            }
          }
        }
      }
    }
    
    // ==== フェーズ3: DNAME合成 ====
    if (!found) {
      bool dname_found = false;
      const char *dname_parent = current_qname;
      while ((dname_parent = strchr_unescaped(dname_parent, '.')) != NULL) {
        dname_parent++;
        if (*dname_parent == '\0') break;
        uint32_t p_hash = calc_fnv1a_str(dname_parent);
        size_t p_idx = p_hash & (current_zone->hash_size - 1);
        for (int i = current_zone->hash_table[p_idx]; i != -1; i = current_zone->records[i].next_record) {
          dns_record_t *rec = &current_zone->records[i];
          if (rec->type_code == 39 && strcasecmp(rec->name, dname_parent) == 0) {
            uint32_t eff_ttl;
            if (!tinydns_record_currently_valid(rec, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &eff_ttl)) continue;
            dname_found = true;
            if (rec->rdata_count == 0) break;

            // 先に DNAME レコード自身を Answer セクションに追加
            dns_record_t rec_copy = *rec;
            rec_copy.ttl_value = eff_ttl;
            if (rec->ecs_subnet_tag != NULL) ecs_used = true;
            if (serialize_dns_record(res, max_res_len, offset, &rec_copy, comp_ctx, NULL, 0xFFFFFFFF) < 0) {
              res[2] |= 0x02;
              if (ecs_used && out_ecs_scope_prefix) *out_ecs_scope_prefix = temp_scope_prefix;
              return;
            }
            (*ancount)++;
            if (dnssec_ok) {
              if (!attach_covering_rrsig(current_zone, p_idx, dname_parent, NULL, 39, res, max_res_len, offset, comp_ctx, ancount)) {
                res[2] |= 0x02;
                if (ecs_used && out_ecs_scope_prefix) *out_ecs_scope_prefix = temp_scope_prefix;
                return;
              }
            }

            // [RFC 6672 §4.1] 合成名長の検証
            size_t prefix_len = dname_parent - current_qname;
            size_t target_len = strlen(rec->rdata[0]);
            if (prefix_len + target_len > 255) {
              // 合成 CNAME は含めず、DNAME のみを載せて YXDOMAIN を返す
              res[3] = (res[3] & 0xF0) | 6; // YXDOMAIN
              if (ecs_used && out_ecs_scope_prefix) *out_ecs_scope_prefix = temp_scope_prefix;
              return;
            }

            char synth_name[256];
            memcpy(synth_name, current_qname, prefix_len);
            int written = snprintf(synth_name + prefix_len, sizeof(synth_name) - prefix_len, "%s", rec->rdata[0]);
            if (written < 0 || (size_t)written >= sizeof(synth_name) - prefix_len || (prefix_len + (size_t)written > 255)) {
              res[3] = (res[3] & 0xF0) | 6; // YXDOMAIN
              if (ecs_used && out_ecs_scope_prefix) *out_ecs_scope_prefix = temp_scope_prefix;
              return;
            }

            // 255 バイト以内の場合は通常通り合成 CNAME を追加して追跡継続
            dns_record_t synth_cname;
            memset(&synth_cname, 0, sizeof(synth_cname));
            synth_cname.name = (char *)current_qname;
            synth_cname.type_code = 5;
            synth_cname.ttl = rec->ttl;
            synth_cname.ttl_value = eff_ttl;
            synth_cname.rdata_count = 1;
            synth_cname.rdata[0] = synth_name;
            if (serialize_dns_record(res, max_res_len, offset, &synth_cname, comp_ctx, NULL, 0xFFFFFFFF) < 0) {
              res[2] |= 0x02;
              if (ecs_used && out_ecs_scope_prefix) *out_ecs_scope_prefix = temp_scope_prefix;
              return;
            }
            (*ancount)++;
            const char *target = synth_name;
            bool loop_detected = false;
            for (int v = 0; v < visited_count; v++) {
              if (domain_names_match_ci(target, visited_qnames[v])) {
                loop_detected = true;
                break;
              }
            }
            if (loop_detected) {
              res[3] &= 0xF0;
              if (ecs_used && out_ecs_scope_prefix) *out_ecs_scope_prefix = temp_scope_prefix;
              return;
            }
            if (visited_count < 16) {
              strlcpy(visited_qnames[visited_count++], target, sizeof(visited_qnames[0]));
            }
            strlcpy(current_qname, synth_name, sizeof(current_qname));
            current_qname_len = prefix_len + (size_t)written;
            current_qname_hash = calc_fnv1a_str(current_qname);
            cname_followed = true; found = true; break;
          }
        }
        if (dname_found) break;
      }
      
      // ==== フェーズ4: ワイルドカード合成 ====
      // RFC 4592 2.2.1 / RFC 4035 3.1.3.3 / RFC 5155 B.2.1: a name that exists only as an Empty Non-Terminal
      // (it has descendants) still EXISTS, so a wildcard must not synthesize an answer for it (NODATA instead).
      if (!dname_found && !name_exists_in_zone(current_zone, current_qname, client_loc, client_ecs_tag, client_loc_tag)) {
        const char *parent = current_qname;
        char wc_name[256];
        wc_name[0] = '*';
        wc_name[1] = '.';
        while ((parent = strchr_unescaped(parent, '.')) != NULL) {
          parent++;
          if (*parent == '\0') break;
          size_t parent_len = current_qname_len - (size_t)(parent - current_qname);
          if (parent_len + 3 > sizeof(wc_name)) break;
          uint32_t wc_hash = calc_fnv1a_continue(FNV1A_WILDCARD_PREFIX_HASH, parent);
          size_t wc_idx = wc_hash & (current_zone->hash_size - 1);
          wc_found = false;
          if (current_zone->hash_table[wc_idx] != -1) {
            memcpy(&wc_name[2], parent, parent_len + 1);
            uint16_t wc_signed_types[64];
            int wc_signed_types_count = 0;
            for (int i = current_zone->hash_table[wc_idx]; i != -1;
                 i = current_zone->records[i].next_record) {
              dns_record_t *rec = &current_zone->records[i];
              if (strcasecmp(rec->name, wc_name) == 0) {
                uint16_t r_class = rec->class_val ? rec->class_val : 1;
                bool class_matches = (qclass == 255 || qclass == r_class);
                if (!class_matches) continue;
                uint32_t eff_ttl;
                if (!tinydns_record_currently_valid(rec, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &eff_ttl)) continue;
                found = true;
                wc_found = true;
                uint16_t rec_type = rec->type_code;
                bool follow_cname = false;
                if (rec_type == 5) {
                  if (qtypes[0] != 5 && qtypes[0] != 255) { follow_cname = true; }
                }
                dns_record_t rec_copy = *rec;
                rec_copy.ttl_value = eff_ttl;
                if (follow_cname) {
                  if (!any_cname_wc_expanded) {
                    any_cname_wc_expanded = true;
                    strncpy(first_wc_qname, current_qname, sizeof(first_wc_qname) - 1);
                    first_wc_qname[sizeof(first_wc_qname) - 1] = '\0';
                    first_wc_zone = current_zone;
                    strncpy(first_wc_apex, db_entry->domain, sizeof(first_wc_apex) - 1);
                    first_wc_apex[sizeof(first_wc_apex) - 1] = '\0';
                  }
                  if (rec->ecs_subnet_tag != NULL) ecs_used = true;
                  if (serialize_dns_record(res, max_res_len, offset, &rec_copy, comp_ctx,
                                           current_qname, 0xFFFFFFFF) < 0) {
                    res[2] |= 0x02;
                    if (ecs_used && out_ecs_scope_prefix) *out_ecs_scope_prefix = temp_scope_prefix;
                    return;
                  } else
                    (*ancount)++;
                  if (dnssec_ok) {
                    if (!attach_covering_rrsig(current_zone, wc_idx, wc_name, current_qname, 5,
                                              res, max_res_len, offset, comp_ctx, ancount)) {
                      res[2] |= 0x02;
                      if (ecs_used && out_ecs_scope_prefix) *out_ecs_scope_prefix = temp_scope_prefix;
                      return;
                    }
                  }
                  if (rec->rdata_count > 0) {
                    const char *target = rec->rdata[0];
                    bool loop_detected = false;
                    for (int v = 0; v < visited_count; v++) {
                      if (domain_names_match_ci(target, visited_qnames[v])) {
                        loop_detected = true;
                        break;
                      }
                    }
                    if (loop_detected) {
                      res[3] &= 0xF0;
                      if (ecs_used && out_ecs_scope_prefix) *out_ecs_scope_prefix = temp_scope_prefix;
                      return;
                    }
                    if (visited_count < 16) {
                      strlcpy(visited_qnames[visited_count++], target, sizeof(visited_qnames[0]));
                    }
                    strlcpy(current_qname, target, sizeof(current_qname));
                    current_qname_len = strlen(current_qname);
                    current_qname_hash = calc_fnv1a_str(current_qname);
                    cname_followed = true;
                  }
                  break;
                } else {
                  if (qtypes[0] == 255 || qtypes[0] == rec_type) {
                    type_matched = true;
                    if (rec->ecs_subnet_tag != NULL) ecs_used = true;
                    if (serialize_dns_record(res, max_res_len, offset, &rec_copy, comp_ctx,
                                             current_qname, 0xFFFFFFFF) < 0) {
                      res[2] |= 0x02;
                      if (ecs_used && out_ecs_scope_prefix) *out_ecs_scope_prefix = temp_scope_prefix;
                      return;
                    } else
                      (*ancount)++;
                    collect_additional_rr_glue(&rec_copy, glue_targets, &glue_target_count, minimal_responses);
                    if (dnssec_ok && rec_type != 46) {
                      bool already_signed = false;
                      for (int s = 0; s < wc_signed_types_count; s++) {
                        if (wc_signed_types[s] == rec_type) {
                          already_signed = true;
                          break;
                        }
                      }
                      if (!already_signed) {
                        if (wc_signed_types_count < (int)(sizeof(wc_signed_types) / sizeof(wc_signed_types[0]))) {
                          wc_signed_types[wc_signed_types_count++] = rec_type;
                        }
                        if (!attach_covering_rrsig(current_zone, wc_idx, wc_name, current_qname, rec_type,
                                                  res, max_res_len, offset, comp_ctx, ancount)) {
                          res[2] |= 0x02;
                          if (ecs_used && out_ecs_scope_prefix) *out_ecs_scope_prefix = temp_scope_prefix;
                          return;
                        }
                      }
                    }
                  }
                }
              }
            }
          }
          if (wc_found)
            break;

          // ★重要: RFC 4592 準拠 (親存在チェック)
          if (name_exists_in_zone(current_zone, parent, client_loc, client_ecs_tag, client_loc_tag))
            break;
        }
      }
    }
    
    // ==== フェーズ5: CNAMEチェーン処理・クロスゾーン切り替え ====
    if (cname_followed) {
      size_t cq_len = current_qname_len, z_len = strlen(db_entry->domain);
      bool in_zone = false;
      if (cq_len >= z_len &&
          strcasecmp(current_qname + cq_len - z_len, db_entry->domain) == 0 &&
          (cq_len == z_len || current_qname[cq_len - z_len - 1] == '.'))
        in_zone = true;
      if (in_zone)
        continue;
      else {
        zone_db_entry_t *new_db_entry = find_zone_in_view(view, current_qname);
        if (new_db_entry) {
          zone_arena_t *new_zone = atomic_load_explicit(&new_db_entry->rcu.active, memory_order_acquire);
          *db_entry_ptr = new_db_entry;
          *current_zone_ptr = new_zone;
          continue;
        } else {
          return;
        }
      }
    }
    
    // ==== フェーズ6: 複数QTYPE追加解決 ====
    bool all_matched = type_matched;
    uint32_t included_mask = 0;
    if (found && num_qtypes > 1) {
      uint32_t final_hash = current_qname_hash;
      size_t final_idx = final_hash & (current_zone->hash_size - 1);
      for (int j = 1; j < num_qtypes; j++) {
        uint16_t qtx = qtypes[j];
        bool this_qtx_failed = false;
        bool qtx_matched = false;
        int saved_glue_target_count = glue_target_count;
        resolve_checkpoint_t cp = save_checkpoint(offset, ancount, nscount, arcount);

        bool qtx_signed = false;
        for (int i = current_zone->hash_table[final_idx]; i != -1; i = current_zone->records[i].next_record) {
          dns_record_t *rec = &current_zone->records[i];
          uint16_t r_class = rec->class_val ? rec->class_val : 1;
          bool class_matches = (qclass == 255 || qclass == r_class);
          if (class_matches && strcasecmp(rec->name, current_qname) == 0 && rec->type_code == qtx) {
            uint32_t eff_ttl;
            if (!tinydns_record_currently_valid(rec, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &eff_ttl)) continue;
            qtx_matched = true;
            dns_record_t rec_copy = *rec;
            rec_copy.ttl_value = eff_ttl;
            if (rec->ecs_subnet_tag != NULL) ecs_used = true;
            if (serialize_dns_record(res, max_res_len, offset, &rec_copy, comp_ctx, NULL, 0xFFFFFFFF) < 0) {
              this_qtx_failed = true; break;
            }
            (*ancount)++;
            collect_additional_rr_glue(&rec_copy, glue_targets, &glue_target_count, minimal_responses);
            if (dnssec_ok && qtx != 46 && !qtx_signed) {
              if (!attach_covering_rrsig(current_zone, final_idx, current_qname, NULL, qtx, res, max_res_len, offset, comp_ctx, ancount)) {
                this_qtx_failed = true; break;
              }
              qtx_signed = true;
            }
          }
        }

        if (!qtx_matched && !this_qtx_failed) {
          const char *parent = current_qname;
          char wc_name[256];
          wc_name[0] = '*'; wc_name[1] = '.';
          while ((parent = strchr_unescaped(parent, '.')) != NULL) {
            parent++; if (*parent == '\0') break;
            size_t parent_len = current_qname_len - (size_t)(parent - current_qname);
            if (parent_len + 3 > sizeof(wc_name)) break;
            uint32_t wc_hash = calc_fnv1a_continue(FNV1A_WILDCARD_PREFIX_HASH, parent);
            size_t wc_idx = wc_hash & (current_zone->hash_size - 1);
            wc_found = false;
            bool wc_qtx_signed = false;
            if (current_zone->hash_table[wc_idx] != -1) {
              memcpy(&wc_name[2], parent, parent_len + 1);
              for (int i = current_zone->hash_table[wc_idx]; i != -1; i = current_zone->records[i].next_record) {
                dns_record_t *rec = &current_zone->records[i];
                uint16_t r_class = rec->class_val ? rec->class_val : 1;
                bool class_matches = (qclass == 255 || qclass == r_class);
                if (class_matches && strcasecmp(rec->name, wc_name) == 0 && rec->type_code == qtx) {
                  uint32_t eff_ttl;
                  if (!tinydns_record_currently_valid(rec, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &eff_ttl)) continue;
                  wc_found = true; qtx_matched = true;
                  dns_record_t rec_copy = *rec;
                  rec_copy.ttl_value = eff_ttl;
                  if (rec->ecs_subnet_tag != NULL) ecs_used = true;
                  if (serialize_dns_record(res, max_res_len, offset, &rec_copy, comp_ctx, current_qname, 0xFFFFFFFF) < 0) {
                    this_qtx_failed = true; break;
                  }
                  (*ancount)++;
                  collect_additional_rr_glue(&rec_copy, glue_targets, &glue_target_count, minimal_responses);
                  if (dnssec_ok && qtx != 46 && !wc_qtx_signed) {
                    if (!attach_covering_rrsig(current_zone, wc_idx, wc_name, current_qname, qtx, res, max_res_len, offset, comp_ctx, ancount)) {
                      this_qtx_failed = true; break;
                    }
                    wc_qtx_signed = true;
                  }
                }
              }
            }
            if (wc_found || this_qtx_failed) break;

            // ★重要: RFC 4592 準拠 (親存在チェック)
            if (name_exists_in_zone(current_zone, parent, client_loc, client_ecs_tag, client_loc_tag))
              break;
          }
        }

        if (this_qtx_failed) {
          restore_checkpoint(&cp, offset, ancount, nscount, arcount);
          glue_target_count = saved_glue_target_count;
          break;
        } else {
          if (!qtx_matched) all_matched = false;
          included_mask |= (1 << j);
        }
      }
    }
    if (qtx_included_out) *qtx_included_out = included_mask;

    // RFC 8020 / RFC 4592 2.2.1: an Empty Non-Terminal (no records of its own, but descendants exist) EXISTS.
    // Asking for it is NODATA (NOERROR), never NXDOMAIN: NXDOMAIN would claim that nothing exists below it.
    bool ent_nodata = false;
    if (!found &&
        name_exists_in_zone(current_zone, current_qname, client_loc, client_ecs_tag, client_loc_tag)) {
      found = true;
      ent_nodata = true;
      all_matched = false;   // no RRset of the requested type(s): a NODATA proof is required
    }

    // ==== フェーズ7: ネガティブ応答(SOA)付加 ====
    if (!found || !type_matched) {
      if (!found)
        res[3] = (res[3] & 0xF0) | 3;
      else
        res[3] &= 0xF0;
      if (!apex_hash_computed) {
        const char *apex_lookup = db_entry->domain;
        char dot_buf[256];
        size_t dlen = strlen(apex_lookup);
        if (dlen > 0 && apex_lookup[dlen - 1] != '.' && dlen + 2 <= sizeof(dot_buf)) {
          memcpy(dot_buf, apex_lookup, dlen);
          dot_buf[dlen] = '.';
          dot_buf[dlen + 1] = '\0';
          uint32_t dh = calc_fnv1a_str(dot_buf);
          size_t di = dh & (current_zone->hash_size - 1);
          if (current_zone->hash_table[di] != -1) {
            apex_lookup = dot_buf;
          }
        }
        apex_hash = calc_fnv1a_str(apex_lookup);
        apex_idx = apex_hash & (current_zone->hash_size - 1);
        apex_hash_computed = true;
      }
      bool soa_found = false;
      for (int i = current_zone->hash_table[apex_idx]; i != -1;
           i = current_zone->records[i].next_record) {
        dns_record_t *rec = &current_zone->records[i];
        if (rec->type_code == 6 &&
            domain_names_match_ci(rec->name, db_entry->domain)) {
          uint32_t eff_ttl;
          if (!tinydns_record_currently_valid(rec, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &eff_ttl)) continue;
          uint32_t minimum_ttl = 3600;
          if (rec->rdata_count >= 7)
            minimum_ttl = parse_ttl_value(rec->rdata[6]);
          dns_record_t rec_copy = *rec;
          rec_copy.ttl_value = eff_ttl;
          if (serialize_dns_record(res, max_res_len, offset, &rec_copy, comp_ctx,
                                   NULL, minimum_ttl) < 0) {
            res[2] |= 0x02;
            return;
          } else
            (*nscount)++;
          if (dnssec_ok) {
            // RFC 2181 §5.2 / RFC 4035 §3.1.5: RRSIG TTL must match covered SOA minimum_ttl
            if (!attach_covering_rrsig_ext(current_zone, apex_idx, db_entry->domain, NULL, 6,
                                           res, max_res_len, offset, comp_ctx, nscount, minimum_ttl)) {
              res[2] |= 0x02;
              return;
            }
          }
          soa_found = true;
          break;
        }
      }
      if (!soa_found) {
        for (size_t i = 0; i < current_zone->count; i++) {
          dns_record_t *rec = &current_zone->records[i];
          if (rec->type_code == 6 &&
              domain_names_match_ci(rec->name, db_entry->domain)) {
            uint32_t eff_ttl;
            if (!tinydns_record_currently_valid(rec, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &eff_ttl)) continue;
            uint32_t minimum_ttl = 3600;
            if (rec->rdata_count >= 7)
              minimum_ttl = parse_ttl_value(rec->rdata[6]);
            dns_record_t rec_copy = *rec;
            rec_copy.ttl_value = eff_ttl;
            if (serialize_dns_record(res, max_res_len, offset, &rec_copy, comp_ctx,
                                     NULL, minimum_ttl) < 0) {
              res[2] |= 0x02;
              return;
            } else
              (*nscount)++;
            if (dnssec_ok) {
              if (!attach_covering_rrsig_ext(current_zone, apex_idx, db_entry->domain, NULL, 6,
                                             res, max_res_len, offset, comp_ctx, nscount, minimum_ttl)) {
                res[2] |= 0x02;
                return;
              }
            }
            break;
          }
        }
      }
    }
    
    // ==== フェーズ8: NSEC付加 ====
    resolve_checkpoint_t nsec_cp = save_checkpoint(offset, ancount, nscount, arcount);
    bool nsec_failed = false;
    dns_record_t *nsec_attached[8];
    int nsec_attached_cnt = 0;
    dns_record_t *attached_nsec3[8];
    int attached_nsec3_cnt = 0;
    if (dnssec_ok && !zone_uses_nsec3(current_zone, db_entry->domain)) {
      if (found && wc_found) {
        // RFC 4035 §3.1.3.3: Wildcard answer proof (QNAME non-existence)
        dns_record_t *cover = find_covering_nsec(current_zone, current_qname);
        if (cover) {
          if (nsec_attached_cnt < 8) nsec_attached[nsec_attached_cnt++] = cover;
          if (serialize_dns_record(res, max_res_len, offset, cover, comp_ctx,
                                   NULL, 0xFFFFFFFF) < 0) {
            nsec_failed = true;
          } else {
            (*nscount)++;
            uint32_t c_hash = calc_fnv1a_str(cover->name);
            size_t c_idx = c_hash & (current_zone->hash_size - 1);
            if (!attach_covering_rrsig(current_zone, c_idx, cover->name, NULL, 47,
                                       res, max_res_len, offset, comp_ctx, nscount)) {
              nsec_failed = true;
            }
          }
        }
        if (!all_matched && !nsec_failed) {
          const char *encloser = find_closest_encloser(current_zone, current_qname, db_entry->domain, client_loc, client_ecs_tag, client_loc_tag);
          if (encloser) {
            char wc_name[256];
            snprintf(wc_name, sizeof(wc_name), "*.%s", encloser);
            uint32_t wc_hash = calc_fnv1a_str(wc_name);
            size_t wc_idx = wc_hash & (current_zone->hash_size - 1);
            for (int i = current_zone->hash_table[wc_idx]; i != -1; i = current_zone->records[i].next_record) {
              dns_record_t *rec = &current_zone->records[i];
              if (rec->type_code == 47 && strcasecmp(rec->name, wc_name) == 0) {
                if (serialize_dns_record(res, max_res_len, offset, rec, comp_ctx, NULL, 0xFFFFFFFF) < 0) {
                  nsec_failed = true;
                } else {
                  (*nscount)++;
                  attach_covering_rrsig(current_zone, wc_idx, wc_name, NULL, 47, res, max_res_len, offset, comp_ctx, nscount);
                }
                break;
              }
            }
          }
        }
      } else if (found && !all_matched) {
        for (int i = current_zone->hash_table[idx]; i != -1;
             i = current_zone->records[i].next_record) {
          dns_record_t *rec = &current_zone->records[i];
          if (rec->type_code == 47 /* NSEC */ &&
              strcasecmp(rec->name, current_qname) == 0) {
            if (rec->rdata_count < 1) break; // 壊れたNSECは無視
            uint32_t eff_ttl;
            if (!tinydns_record_currently_valid(rec, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &eff_ttl)) continue;
            dns_record_t rec_copy = *rec;
            rec_copy.ttl_value = eff_ttl;
            if (serialize_dns_record(res, max_res_len, offset, &rec_copy, comp_ctx,
                                     NULL, 0xFFFFFFFF) < 0) {
              nsec_failed = true; break;
            }
            (*nscount)++;
            if (!attach_covering_rrsig(current_zone, idx, current_qname, NULL, 47,
                                       res, max_res_len, offset, comp_ctx, nscount)) {
              nsec_failed = true; break;
            }
            break;
          }
        }
        if (ent_nodata && !nsec_failed && nsec_attached_cnt == 0) {
          // An ENT owns no NSEC; the NSEC that covers it (its next name is a descendant) proves it exists.
          dns_record_t *cover = find_covering_nsec(current_zone, current_qname);
          if (cover) {
            if (nsec_attached_cnt < 8) nsec_attached[nsec_attached_cnt++] = cover;
            if (serialize_dns_record(res, max_res_len, offset, cover, comp_ctx, NULL, 0xFFFFFFFF) < 0) {
              nsec_failed = true;
            } else {
              (*nscount)++;
              uint32_t c_hash = calc_fnv1a_str(cover->name);
              size_t c_idx = c_hash & (current_zone->hash_size - 1);
              if (!attach_covering_rrsig(current_zone, c_idx, cover->name, NULL, 47,
                                         res, max_res_len, offset, comp_ctx, nscount)) {
                nsec_failed = true;
              }
            }
          }
        }
      } else if (!found) {
        dns_record_t *cover = find_covering_nsec(current_zone, current_qname);
        if (cover) {
          if (nsec_attached_cnt < 8) nsec_attached[nsec_attached_cnt++] = cover;
          if (serialize_dns_record(res, max_res_len, offset, cover, comp_ctx,
                                   NULL, 0xFFFFFFFF) < 0) {
            nsec_failed = true;
          } else {
            (*nscount)++;
            uint32_t c_hash = calc_fnv1a_str(cover->name);
            size_t c_idx = c_hash & (current_zone->hash_size - 1);
            if (!attach_covering_rrsig(current_zone, c_idx, cover->name, NULL, 47,
                                       res, max_res_len, offset, comp_ctx, nscount)) {
              nsec_failed = true;
            }
          }
        }

        if (!nsec_failed) {
          const char *encloser = find_closest_encloser(current_zone, current_qname, db_entry->domain, client_loc, client_ecs_tag, client_loc_tag);
          if (encloser) {
            char wc_name[256];
            int written = snprintf(wc_name, sizeof(wc_name), "*.%s", encloser);
            if (written > 0 && (size_t)written < sizeof(wc_name)) {
              if (!cover || !nsec_covers_name(cover, wc_name)) {
                dns_record_t *wc_cover = find_covering_nsec(current_zone, wc_name);
                if (wc_cover && wc_cover != cover) {
                  if (serialize_dns_record(res, max_res_len, offset, wc_cover, comp_ctx,
                                           NULL, 0xFFFFFFFF) < 0) {
                    nsec_failed = true;
                  } else {
                    (*nscount)++;
                    uint32_t wc_hash = calc_fnv1a_str(wc_cover->name);
                    size_t wc_idx = wc_hash & (current_zone->hash_size - 1);
                    if (!attach_covering_rrsig(current_zone, wc_idx, wc_cover->name, NULL, 47,
                                               res, max_res_len, offset, comp_ctx, nscount)) {
                      nsec_failed = true;
                    }
                  }
                }
              }
            }
          }
        }
      }
    } else if (dnssec_ok && zone_uses_nsec3(current_zone, db_entry->domain)) {
      dns_record_t *param_rec = NULL;
      if (!apex_hash_computed) {
        apex_hash = calc_fnv1a_str(db_entry->domain);
        apex_idx = apex_hash & (current_zone->hash_size - 1);
        apex_hash_computed = true;
      }
      for (int i = current_zone->hash_table[apex_idx]; i != -1; i = current_zone->records[i].next_record) {
        if (current_zone->records[i].type_code == 51 &&
            domain_names_match_ci(current_zone->records[i].name, db_entry->domain)) {
          param_rec = &current_zone->records[i];
          break;
        }
      }
      if (param_rec && param_rec->rdata_count >= 4) {
        uint8_t algo = (uint8_t)atoi(param_rec->rdata[0]);
        uint16_t iterations = (uint16_t)atoi(param_rec->rdata[2]);
        uint8_t salt[64];
        size_t salt_len = hex_to_bytes(param_rec->rdata[3], salt, sizeof(salt));

        if (found && wc_found) {
          // RFC 5155 §7.2.5 & §8.5: Wildcard answer proof (Closest Encloser & Next Closer covering)
          const char *encloser = find_closest_encloser(current_zone, current_qname, db_entry->domain, client_loc, client_ecs_tag, client_loc_tag);
          if (!encloser) encloser = db_entry->domain;
          char ce_hash[64];
          if (compute_nsec3_hash(encloser, algo, iterations, salt, salt_len, ce_hash, sizeof(ce_hash))) {
            dns_record_t *ce_rec = find_matching_nsec3(current_zone, ce_hash, db_entry->domain);
            if (ce_rec) {
              if (!attach_nsec3_record(current_zone, ce_rec, res, max_res_len, offset, comp_ctx, nscount, attached_nsec3, &attached_nsec3_cnt)) {
                nsec_failed = true;
              }
            }
          }

          char nc_name[256];
          if (!nsec_failed && find_next_closer_name(current_qname, encloser, nc_name, sizeof(nc_name))) {
            char nc_hash[64];
            if (compute_nsec3_hash(nc_name, algo, iterations, salt, salt_len, nc_hash, sizeof(nc_hash))) {
              dns_record_t *nc_cover = find_covering_nsec3(current_zone, nc_hash);
              if (nc_cover) {
                if (!attach_nsec3_record(current_zone, nc_cover, res, max_res_len, offset, comp_ctx, nscount, attached_nsec3, &attached_nsec3_cnt)) {
                  nsec_failed = true;
                }
              }
            }
          }

          if (!all_matched && !nsec_failed) {
            char wc_name[256];
            snprintf(wc_name, sizeof(wc_name), "*.%s", encloser);
            char wc_hash[64];
            if (compute_nsec3_hash(wc_name, algo, iterations, salt, salt_len, wc_hash, sizeof(wc_hash))) {
              dns_record_t *wc_rec = find_matching_nsec3(current_zone, wc_hash, db_entry->domain);
              if (wc_rec) {
                if (!attach_nsec3_record(current_zone, wc_rec, res, max_res_len, offset, comp_ctx, nscount, attached_nsec3, &attached_nsec3_cnt)) {
                  nsec_failed = true;
                }
              }
            }
          }
        } else if (found && !all_matched) {
          // NODATA: matching NSEC3 for current_qname
          char q_hash[64];
          if (compute_nsec3_hash(current_qname, algo, iterations, salt, salt_len, q_hash, sizeof(q_hash))) {
            dns_record_t *m_rec = find_matching_nsec3(current_zone, q_hash, db_entry->domain);
            if (m_rec) {
              if (!attach_nsec3_record(current_zone, m_rec, res, max_res_len, offset, comp_ctx, nscount, attached_nsec3, &attached_nsec3_cnt)) {
                nsec_failed = true;
              }
            }
          }
        } else if (!found) {
          // NXDOMAIN: Closest Encloser, Next Closer, Wildcard
          const char *encloser = find_closest_encloser(current_zone, current_qname, db_entry->domain, client_loc, client_ecs_tag, client_loc_tag);
          if (!encloser) encloser = db_entry->domain;
          char ce_hash[64];
          if (compute_nsec3_hash(encloser, algo, iterations, salt, salt_len, ce_hash, sizeof(ce_hash))) {
            dns_record_t *ce_rec = find_matching_nsec3(current_zone, ce_hash, db_entry->domain);
            if (ce_rec) {
              if (!attach_nsec3_record(current_zone, ce_rec, res, max_res_len, offset, comp_ctx, nscount, attached_nsec3, &attached_nsec3_cnt)) {
                nsec_failed = true;
              }
            }
          }

          char nc_name[256];
          if (!nsec_failed && find_next_closer_name(current_qname, encloser, nc_name, sizeof(nc_name))) {
            char nc_hash[64];
            if (compute_nsec3_hash(nc_name, algo, iterations, salt, salt_len, nc_hash, sizeof(nc_hash))) {
              dns_record_t *nc_cover = find_covering_nsec3(current_zone, nc_hash);
              if (nc_cover) {
                if (!attach_nsec3_record(current_zone, nc_cover, res, max_res_len, offset, comp_ctx, nscount, attached_nsec3, &attached_nsec3_cnt)) {
                  nsec_failed = true;
                }
              }
            }
          }

          char wc_name[256];
          snprintf(wc_name, sizeof(wc_name), "*.%s", encloser);
          char wc_hash[64];
          if (!nsec_failed && compute_nsec3_hash(wc_name, algo, iterations, salt, salt_len, wc_hash, sizeof(wc_hash))) {
            dns_record_t *wc_cover = find_covering_nsec3(current_zone, wc_hash);
            if (wc_cover) {
              if (!attach_nsec3_record(current_zone, wc_cover, res, max_res_len, offset, comp_ctx, nscount, attached_nsec3, &attached_nsec3_cnt)) {
                nsec_failed = true;
              }
            }
          }
        }
      }
    }

    if (dnssec_ok && any_cname_wc_expanded && !nsec_failed) {
      zone_arena_t *wc_zone = first_wc_zone ? first_wc_zone : current_zone;
      const char *wc_apex = first_wc_apex[0] ? first_wc_apex : db_entry->domain;
      if (!zone_uses_nsec3(wc_zone, wc_apex)) {
        dns_record_t *cover = find_covering_nsec(wc_zone, first_wc_qname);
        if (cover) {
          bool already_attached = false;
          for (int a = 0; a < nsec_attached_cnt; a++) {
            if (nsec_attached[a] == cover) { already_attached = true; break; }
          }
          if (!already_attached) {
            if (nsec_attached_cnt < 8) nsec_attached[nsec_attached_cnt++] = cover;
            if (serialize_dns_record(res, max_res_len, offset, cover, comp_ctx, NULL, 0xFFFFFFFF) < 0) {
              nsec_failed = true;
            } else {
              (*nscount)++;
              uint32_t c_hash = calc_fnv1a_str(cover->name);
              size_t c_idx = c_hash & (wc_zone->hash_size - 1);
              if (!attach_covering_rrsig(wc_zone, c_idx, cover->name, NULL, 47,
                                         res, max_res_len, offset, comp_ctx, nscount)) {
                nsec_failed = true;
              }
            }
          }
        }
      } else {
        uint32_t a_hash = calc_fnv1a_str(wc_apex);
        size_t a_idx = a_hash & (wc_zone->hash_size - 1);
        dns_record_t *p_rec = NULL;
        for (int i = wc_zone->hash_table[a_idx]; i != -1; i = wc_zone->records[i].next_record) {
          if (wc_zone->records[i].type_code == 51 &&
              domain_names_match_ci(wc_zone->records[i].name, wc_apex)) {
            p_rec = &wc_zone->records[i];
            break;
          }
        }
        if (p_rec && p_rec->rdata_count >= 4) {
          uint8_t algo = (uint8_t)atoi(p_rec->rdata[0]);
          uint16_t iterations = (uint16_t)atoi(p_rec->rdata[2]);
          uint8_t salt[64];
          size_t salt_len = hex_to_bytes(p_rec->rdata[3], salt, sizeof(salt));

          const char *encloser = find_closest_encloser(wc_zone, first_wc_qname, wc_apex, client_loc, client_ecs_tag, client_loc_tag);
          if (!encloser) encloser = wc_apex;
          char ce_hash[64];
          if (compute_nsec3_hash(encloser, algo, iterations, salt, salt_len, ce_hash, sizeof(ce_hash))) {
            dns_record_t *ce_rec = find_matching_nsec3(wc_zone, ce_hash, wc_apex);
            if (ce_rec) {
              if (!attach_nsec3_record(wc_zone, ce_rec, res, max_res_len, offset, comp_ctx, nscount, attached_nsec3, &attached_nsec3_cnt)) {
                nsec_failed = true;
              }
            }
          }

          char nc_name[256];
          if (!nsec_failed && find_next_closer_name(first_wc_qname, encloser, nc_name, sizeof(nc_name))) {
            char nc_hash[64];
            if (compute_nsec3_hash(nc_name, algo, iterations, salt, salt_len, nc_hash, sizeof(nc_hash))) {
              dns_record_t *nc_cover = find_covering_nsec3(wc_zone, nc_hash);
              if (nc_cover) {
                if (!attach_nsec3_record(wc_zone, nc_cover, res, max_res_len, offset, comp_ctx, nscount, attached_nsec3, &attached_nsec3_cnt)) {
                  nsec_failed = true;
                }
              }
            }
          }
        }
      }
    }
    
    if (nsec_failed) {
      restore_checkpoint(&nsec_cp, offset, ancount, nscount, arcount);
    }
    
    // ==== フェーズ9: Authority NS/Glue付加 ====
    bool needs_ns = false;
    if (qtypes[0] != 2 && qtypes[0] != 255) { needs_ns = true; }
    if (type_matched && !minimal_responses && needs_ns) {
      if (!apex_hash_computed) {
        apex_hash = calc_fnv1a_str(db_entry->domain);
        apex_idx = apex_hash & (current_zone->hash_size - 1);
        apex_hash_computed = true;
      }
      for (int i = current_zone->hash_table[apex_idx]; i != -1;
           i = current_zone->records[i].next_record) {
        dns_record_t *rec = &current_zone->records[i];
        if (rec->type_code == 2 &&
            domain_names_match_ci(rec->name, db_entry->domain)) {
          uint32_t eff_ttl;
          if (!tinydns_record_currently_valid(rec, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &eff_ttl)) continue;
          dns_record_t rec_copy = *rec;
          rec_copy.ttl_value = eff_ttl;
          if (serialize_dns_record(res, max_res_len, offset, &rec_copy, comp_ctx,
                                   NULL, 0xFFFFFFFF) < 0) {
            res[2] |= 0x02;
            return;
          } else {
            (*nscount)++;
            if (rec->rdata_count > 0) {
              collect_additional_rr_glue(&rec_copy, glue_targets, &glue_target_count, minimal_responses);
            }
          }
        }
      }
    }

    // ==== フェーズ10: Additional Glue付加 ====
    if (!minimal_responses && glue_target_count > 0 && policy != ADDITIONAL_AUTH_NO) {
      for (int k = 0; k < glue_target_count; k++) {
        if (!append_glue_records(current_zone, glue_targets[k], db_entry->domain,
                                 res, max_res_len, offset, comp_ctx, arcount,
                                 client_loc, client_ecs_tag, client_loc_tag, policy, view)) {
          break; // バッファ上限に達した場合は以後のグルー追加を中断 (RFC 2181 §9)
        }
      }
    }

    chain_exhausted = false;
    break;
  }
  if (chain_exhausted) {
    // 既に 1 つ以上の CNAME が Answer に格納されている場合は SERVFAIL にロールバックしない
    if (*ancount > initial_ancount) {
      // 解決できた CNAME 群を保持して正常終了 (NOERROR)
      res[3] &= 0xF0;
    } else {
      res[3] = (res[3] & 0xF0) | 0x02; // SERVFAIL
      *offset = initial_offset;
      *ancount = initial_ancount;
      *nscount = initial_nscount;
      *arcount = initial_arcount;
    }
    if (out_ecs_scope_prefix) *out_ecs_scope_prefix = 0;
  } else {
    if (ecs_used && out_ecs_scope_prefix) {
      *out_ecs_scope_prefix = temp_scope_prefix;
    } else if (out_ecs_scope_prefix) {
      *out_ecs_scope_prefix = 0;
    }
  }
}

size_t get_question_end_offset(const uint8_t *pkt, size_t len, uint16_t qdcount) {
    size_t offset = DNS_HEADER_SIZE;
    for (int k = 0; k < qdcount; k++) {
        while (offset < len) {
            uint8_t l = pkt[offset];
            if (l == 0) { offset++; break; }
            /* [C-1] 圧縮ポインタの境界チェック */
            if ((l & 0xC0) == 0xC0) {
                if (offset + 2 > len) return len;
                offset += 2; break;
            }
            /* [C-1] ラベル読み越し防止: offset + l + 1 が len を超えないことを確認 */
            if (offset + 1 + l + 1 > len) return len;
            offset += l + 1;
        }
        /* [C-1] QTYPE/QCLASS (4バイト) の境界チェック */
        if (offset + 4 > len) return len;
        offset += 4; // QTYPE, QCLASS
    }
    return (offset <= len) ? offset : len;
}

STATIC_TEST program_plugin_t *find_program_plugin(const char *domain) {
  if (!domain) return NULL;
  for (int i = 0; i < g_program_plugins_count; i++) {
    if (strcasecmp(g_program_plugins[i].domain, domain) == 0)
      return &g_program_plugins[i];
  }
  return NULL;
}

STATIC_TEST int64_t monotonic_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* deadline(monotonic_ms()基準の絶対時刻)までの残り時間をmsで返す。
 * 既に締切を過ぎていれば0を返す(呼び出し先のwrite_all_timeout/read_all_timeoutは
 * timeout_ms=0で即座にタイムアウト扱いになる)。 */
STATIC_TEST uint32_t remaining_ms(int64_t deadline) {
  int64_t rem = deadline - monotonic_ms();
  if (rem <= 0) return 0;
  if (rem > UINT32_MAX) return UINT32_MAX; /* 実際には発生しないが念のため */
  return (uint32_t)rem;
}

void compute_program_zone_fingerprint(const zone_config_t *z, char *out, size_t out_cap) {
  size_t pos = 0;
  pos += (size_t)snprintf(out + pos, out_cap - pos, "path=%s|user=%s|timeout=%u|maxfail=%u|disable_tc=%d|args=",
                          z->program_path ? z->program_path : "",
                          z->program_user ? z->program_user : "",
                          z->program_timeout_ms, z->program_max_failures,
                          z->disable_auto_tc_flag ? 1 : 0);
  for (int i = 0; i < z->program_args_count && pos < out_cap; i++) {
    pos += (size_t)snprintf(out + pos, out_cap - pos, "%s;", z->program_args[i]);
  }
}

/* type "program"/"forward" ゾーンで、実際の応答を得られなかった場合に
 * 合成SERVFAILパケットを構築して返す共通ヘルパー。
 * (以前は単に0を返しており、これは「応答なし(サイレントドロップ)」を
 *  意味していた。クライアント視点ではタイムアウトとSERVFAILは挙動が
 *  大きく異なるため、ログの記述に合わせて実装側もSERVFAILを返す。) */
STATIC_TEST int build_synthetic_servfail(const uint8_t *req, size_t req_len,
                                       uint8_t *res, size_t max_res_len) {
  if (req_len < DNS_HEADER_SIZE || max_res_len < DNS_HEADER_SIZE) return 0; // 応答しようがない
  uint16_t qdcount = (req[4] << 8) | req[5];
  size_t q_end = (size_t)get_question_end_offset(req, req_len, qdcount);
  size_t copy_len = q_end > max_res_len ? max_res_len : q_end;
  memcpy(res, req, copy_len);
  res[2] |= 0x80;              // QR=1
  res[2] &= ~0x06;             // AA=0, TC=0 をクリア
  res[3] = (res[3] & 0xF0) | 2; // RCODE=2 (SERVFAIL), RA/Z/AD/CDは維持
  /* [M-4] 質問セクションが切り詰められた場合 QDCOUNT と実内容が乖離しないよう
   * copy_len < q_end (切り詰めが発生した) なら QDCOUNT=0 に設定する。
   * 切り詰めなし (q_end <= max_res_len) の場合はそのまま維持 (SERVFAIL は QDCOUNT=1 許容)。*/
  if (q_end > max_res_len) {
    res[4] = 0; res[5] = 0; // QDCOUNT=0 (切り詰め時)
  }
  res[6] = 0; res[7] = 0;   // ANCOUNT=0
  res[8] = 0; res[9] = 0;   // NSCOUNT=0
  res[10] = 0; res[11] = 0; // ARCOUNT=0
  return (int)copy_len;
}

STATIC_TEST ssize_t write_all_timeout(int fd, const uint8_t *buf, size_t len, uint32_t timeout_ms) {
  size_t written = 0;
  struct timespec start_ts, now_ts;
  clock_gettime(CLOCK_MONOTONIC, &start_ts);

  while (written < len) {
    clock_gettime(CLOCK_MONOTONIC, &now_ts);
    int64_t elapsed_ms = (now_ts.tv_sec - start_ts.tv_sec) * 1000 + (now_ts.tv_nsec - start_ts.tv_nsec) / 1000000;
    if (elapsed_ms >= timeout_ms) return -1;
    int rem_ms = (int)(timeout_ms - elapsed_ms);

    struct pollfd pfd = { .fd = fd, .events = POLLOUT, .revents = 0 };
    int ret = poll(&pfd, 1, rem_ms);
    if (ret <= 0) return -1;

    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) return -1;
    if (pfd.revents & POLLOUT) {
      ssize_t n = write(fd, buf + written, len - written);
      if (n <= 0) {
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        return -1;
      }
      written += (size_t)n;
    }
  }
  return (ssize_t)written;
}

STATIC_TEST ssize_t read_all_timeout(int fd, uint8_t *buf, size_t len, uint32_t timeout_ms) {
  size_t nread = 0;
  struct timespec start_ts, now_ts;
  clock_gettime(CLOCK_MONOTONIC, &start_ts);

  while (nread < len) {
    clock_gettime(CLOCK_MONOTONIC, &now_ts);
    int64_t elapsed_ms = (now_ts.tv_sec - start_ts.tv_sec) * 1000 + (now_ts.tv_nsec - start_ts.tv_nsec) / 1000000;
    if (elapsed_ms >= timeout_ms) return -1;
    int rem_ms = (int)(timeout_ms - elapsed_ms);

    struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
    int ret = poll(&pfd, 1, rem_ms);
    if (ret <= 0) return -1;

    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
      if (!(pfd.revents & POLLIN)) return -1;
    }
    if (pfd.revents & POLLIN) {
      ssize_t n = read(fd, buf + nread, len - nread);
      if (n <= 0) {
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        return -1;
      }
      nread += (size_t)n;
    }
  }
  return (ssize_t)nread;
}

STATIC_TEST int dispatch_to_program_zone(const char *domain, const uint8_t *req, size_t req_len,
                                    uint8_t *res, size_t max_res_len,
                                    const char *client_ip, bool is_tcp) {
  program_plugin_t *plugin = find_program_plugin(domain);
  if (!plugin || atomic_load_explicit(&plugin->dead, memory_order_acquire)) {
    return build_synthetic_servfail(req, req_len, res, max_res_len); // M-1
  }

  pthread_mutex_lock(&plugin->lock);

  // H-3: 1クエリ全体で共有する絶対締切。以降の全I/O呼び出しは
  // 「plugin->timeout_ms」ではなく「この締切までの残り時間」を使う。
  int64_t deadline = monotonic_ms() + plugin->timeout_ms;

  char header[80];
  int hlen = snprintf(header, sizeof(header), "QUERY %s %s\n",
                      is_tcp ? "tcp" : "udp", client_ip ? client_ip : "127.0.0.1");

  uint8_t len_prefix[2] = { (uint8_t)(req_len >> 8), (uint8_t)(req_len & 0xFF) };

  bool ok = true;
  if (write_all_timeout(plugin->stdin_fd, (const uint8_t *)header, (size_t)hlen, remaining_ms(deadline)) != hlen) ok = false;
  if (ok && write_all_timeout(plugin->stdin_fd, len_prefix, 2, remaining_ms(deadline)) != 2) ok = false;
  if (ok && write_all_timeout(plugin->stdin_fd, req, req_len, remaining_ms(deadline)) != (ssize_t)req_len) ok = false;

  int result_len = 0;
  if (ok) {
    uint8_t resp_len_prefix[2];
    if (read_all_timeout(plugin->stdout_fd, resp_len_prefix, 2, remaining_ms(deadline)) == 2) {
      uint32_t resp_len = ((uint32_t)resp_len_prefix[0] << 8) | resp_len_prefix[1];
      if (resp_len == 0) {
        result_len = 0; // 意図的な無応答
        ok = true;
      } else if (resp_len > 65535) {
        syslog(LOG_ERR, "[Plugin] zone '%s' returned response > 65535 bytes (%u); rejecting with SERVFAIL",
               domain, (unsigned int)resp_len);
        ok = false;
      } else if (plugin->disable_auto_tc_flag) {
        // disable-auto-tc-flag yes (default): do not truncate or force TC=1; send full response as-is (up to 65535)
        if (read_all_timeout(plugin->stdout_fd, res, resp_len, remaining_ms(deadline)) == (ssize_t)resp_len) {
          result_len = (int)resp_len;
          ok = true;
        } else {
          ok = false;
        }
      } else if (resp_len <= max_res_len) {
        if (read_all_timeout(plugin->stdout_fd, res, resp_len, remaining_ms(deadline)) == (ssize_t)resp_len) {
          result_len = (int)resp_len;
          ok = true;
        } else {
          ok = false;
        }
      } else {
        syslog(LOG_INFO, "[Plugin] zone '%s' returned oversized response (%u > %zu); truncating with TC=1",
               domain, (unsigned int)resp_len, max_res_len);
        /* 最初の max_res_len 分を res に読み込み、残りを読み捨ててパイプの同期を保つ。
         * 共有締切の残り時間を使うため、宣言長がどれだけ大きくても合計の待ち時間は plugin->timeout_ms を超えない。 */
        size_t first_chunk = max_res_len;
        if (read_all_timeout(plugin->stdout_fd, res, first_chunk, remaining_ms(deadline)) == (ssize_t)first_chunk) {
          size_t remaining = resp_len - first_chunk;
          uint8_t drain_buf[512];
          while (remaining > 0) {
            size_t chunk = remaining < sizeof(drain_buf) ? remaining : sizeof(drain_buf);
            if (read_all_timeout(plugin->stdout_fd, drain_buf, chunk, remaining_ms(deadline)) != (ssize_t)chunk) {
              ok = false;
              break;
            }
            remaining -= chunk;
          }
          if (ok) {
            // TCビットをセットし、質問セクション以降をクリアして切り詰め応答とする
            res[0] = req[0]; res[1] = req[1]; // クエリのトランザクションIDを反映
            res[2] |= 0x82;                   // QR=1, TC=1
            res[4] = req[4]; res[5] = req[5]; // QDCOUNT
            res[6] = 0; res[7] = 0;           // ANCOUNT=0
            res[8] = 0; res[9] = 0;           // NSCOUNT=0
            res[10] = 0; res[11] = 0;         // ARCOUNT=0
            uint16_t qdcount = (req[4] << 8) | req[5];
            size_t qlen = get_question_end_offset(res, first_chunk, qdcount);
            if (qlen < DNS_HEADER_SIZE || qlen > first_chunk) {
              size_t req_qlen = get_question_end_offset(req, req_len, qdcount);
              if (req_qlen >= DNS_HEADER_SIZE && req_qlen <= max_res_len) {
                memcpy(res + DNS_HEADER_SIZE, req + DNS_HEADER_SIZE, req_qlen - DNS_HEADER_SIZE);
                qlen = req_qlen;
              } else {
                qlen = DNS_HEADER_SIZE;
              }
            }
            result_len = (int)qlen;
          }
        } else {
          ok = false;
        }
      }
    } else {
      ok = false;
    }
  }

  if (!ok) {
    unsigned int f = atomic_fetch_add_explicit(&plugin->consecutive_failures, 1, memory_order_acq_rel) + 1;
    syslog(LOG_ERR, "[Plugin] zone '%s' communication failure (%u/%u)", domain, f, plugin->max_failures);
    if (f >= plugin->max_failures) {
      atomic_store_explicit(&plugin->dead, true, memory_order_release);
      syslog(LOG_CRIT, "[Plugin] zone '%s' exceeded max failures; marking dead "
             "(will return SERVFAIL until restart)", domain);
      if (plugin->pid > 0) {
        kill(plugin->pid, SIGKILL);
        waitpid(plugin->pid, NULL, WNOHANG);
      }
    }
    result_len = build_synthetic_servfail(req, req_len, res, max_res_len); // M-1
  } else {
    atomic_store_explicit(&plugin->consecutive_failures, 0, memory_order_relaxed);
  }

  pthread_mutex_unlock(&plugin->lock);
  return result_len;
}

/* reqのQuestion section(ヘッダ12バイトの直後から、QNAME + QTYPE/QCLASSの4バイトを
 * 含む部分)が、respの中に(先頭12バイトの直後に)存在するかを確認する。
 * QNAMEのドメイン名ラベル文字はRFCに準拠して大文字小文字を区別せず(case-insensitive)
 * 比較し、末尾のQTYPE/QCLASSは完全一致を検証する。 */
STATIC_TEST bool question_section_matches(const uint8_t *resp, size_t resp_len,
                                     const uint8_t *req, size_t req_len) {
  if (req_len <= DNS_HEADER_SIZE || resp_len <= DNS_HEADER_SIZE) return false;
  size_t roff = DNS_HEADER_SIZE;
  size_t soff = DNS_HEADER_SIZE;

  // QNAME のラベル比較 (case-insensitive)
  while (roff < req_len && soff < resp_len) {
    uint8_t rlen = req[roff];
    uint8_t slen = resp[soff];
    if (rlen != slen) return false;
    if (rlen == 0) {
      roff++;
      soff++;
      break; // QNAME 終端
    }
    if (rlen > 63 || roff + 1 + rlen > req_len || soff + 1 + slen > resp_len) return false;
    for (uint8_t j = 0; j < rlen; j++) {
      uint8_t rc = req[roff + 1 + j];
      uint8_t sc = resp[soff + 1 + j];
      if (rc >= 'A' && rc <= 'Z') rc += ('a' - 'A');
      if (sc >= 'A' && sc <= 'Z') sc += ('a' - 'A');
      if (rc != sc) return false;
    }
    roff += 1 + rlen;
    soff += 1 + slen;
  }

  // QTYPE (2バイト) + QCLASS (2バイト) の比較
  if (roff + 4 > req_len || soff + 4 > resp_len) return false;
  return memcmp(req + roff, resp + soff, 4) == 0;
}

STATIC_TEST ssize_t forward_via_tcp(const struct sockaddr_storage *ss, size_t ss_len,
                               const uint8_t *query, size_t query_len,
                               uint8_t *resp_out, size_t resp_out_cap,
                               uint32_t timeout_ms) {
  if (!ss || !query || !resp_out) return -1;
  int fd = broker_connect(ss->ss_family, SOCK_STREAM, (struct sockaddr *)ss, ss_len);
  if (fd < 0) return -1;

  uint8_t len_prefix[2] = { (uint8_t)(query_len >> 8), (uint8_t)(query_len & 0xFF) };
  if (write_all_timeout(fd, len_prefix, 2, timeout_ms) != 2 ||
      write_all_timeout(fd, query, query_len, timeout_ms) != (ssize_t)query_len) {
    close(fd);
    return -1;
  }

  uint8_t resp_len_prefix[2];
  if (read_all_timeout(fd, resp_len_prefix, 2, timeout_ms) != 2) { close(fd); return -1; }
  uint16_t resp_len = (resp_len_prefix[0] << 8) | resp_len_prefix[1];
  if (resp_len == 0 || resp_len > resp_out_cap) { close(fd); return -1; }

  ssize_t got = read_all_timeout(fd, resp_out, resp_len, timeout_ms);
  close(fd);
  return got;
}

_Thread_local static uint8_t s_forward_req_buf[65535];
_Thread_local static uint8_t s_forward_res_buf[65535];

STATIC_TEST int dispatch_forward_zone(zone_config_t *zcfg, const uint8_t *req, size_t req_len,
                                 uint8_t *res, size_t max_res_len) {
  if (req_len < DNS_HEADER_SIZE || zcfg->forwarders_count == 0) {
    return build_synthetic_servfail(req, req_len, res, max_res_len);
  }
  if (req_len > sizeof(s_forward_req_buf)) {
    return build_synthetic_servfail(req, req_len, res, max_res_len);
  }

  // H-3: 1クエリ全体で共有する絶対締切。以降の全I/O呼び出しは
  // 各フォワーダーにフル分与せず、この締切までの残り時間を使う。
  uint32_t total_budget = zcfg->forward_timeout_ms > 0 ? zcfg->forward_timeout_ms : 2000;
  int64_t deadline = monotonic_ms() + total_budget;

  memcpy(s_forward_req_buf, req, req_len);
  uint16_t fresh_id = (uint16_t)(arc4random() & 0xFFFF);
  s_forward_req_buf[0] = fresh_id >> 8;
  s_forward_req_buf[1] = fresh_id & 0xFF;

  for (int i = 0; i < zcfg->forwarders_count; i++) {
    uint32_t rem = remaining_ms(deadline);
    if (rem == 0) {
      syslog(LOG_WARNING, "[Forward] zone '%s': total timeout budget (%ums) expired; stopping forwarder loop",
             zcfg->domain, total_budget);
      break;
    }

    ip_port_t *fwd = &zcfg->forwarders[i];
    struct sockaddr_storage ss;
    size_t ss_len = resolve_ip_port_to_sockaddr(fwd->ip, fwd->port, &ss);
    if (ss_len == 0) {
      syslog(LOG_ERR, "[Forward] zone '%s': forwarder '%s' is not a valid IP address, skipping",
             zcfg->domain, fwd->ip);
      continue;
    }

    int sock = broker_connect(ss.ss_family, SOCK_DGRAM, (struct sockaddr *)&ss, ss_len);
    if (sock < 0) {
      syslog(LOG_WARNING, "[Forward] zone '%s': connect to forwarder '%s:%d' failed",
             zcfg->domain, fwd->ip, fwd->port);
      continue;
    }

    ssize_t got = -1;
    if (send(sock, s_forward_req_buf, req_len, 0) == (ssize_t)req_len) {
      struct pollfd pfd = { .fd = sock, .events = POLLIN };
      if (poll(&pfd, 1, (int)rem) > 0)
        got = recv(sock, s_forward_res_buf, sizeof(s_forward_res_buf), 0);
    }
    close(sock);

    if (got < (ssize_t)DNS_HEADER_SIZE) {
      syslog(LOG_WARNING, "[Forward] zone '%s': forwarder '%s:%d' timed out or failed, trying next",
             zcfg->domain, fwd->ip, fwd->port);
      continue;
    }

    uint16_t resp_id = (s_forward_res_buf[0] << 8) | s_forward_res_buf[1];
    if (resp_id != fresh_id || !(s_forward_res_buf[2] & 0x80) ||
        !question_section_matches(s_forward_res_buf, (size_t)got, req, req_len)) {
      syslog(LOG_WARNING, "[Forward] zone '%s': forwarder '%s:%d' returned a mismatched "
             "response (id/question mismatch), discarding", zcfg->domain, fwd->ip, fwd->port);
      continue;
    }

    if (s_forward_res_buf[2] & 0x02) { // TC bit
      uint32_t rem_tcp = remaining_ms(deadline);
      if (rem_tcp > 0) {
        ssize_t tcp_got = forward_via_tcp(&ss, ss_len, s_forward_req_buf, req_len,
                                          s_forward_res_buf, sizeof(s_forward_res_buf), rem_tcp);
        if (tcp_got >= (ssize_t)DNS_HEADER_SIZE) {
          uint16_t tcp_resp_id = (s_forward_res_buf[0] << 8) | s_forward_res_buf[1];
          if (tcp_resp_id == fresh_id && (s_forward_res_buf[2] & 0x80) &&
              question_section_matches(s_forward_res_buf, (size_t)tcp_got, req, req_len)) {
            got = tcp_got;
          }
        }
      }
      // TCPフォールバックが失敗した場合は、UDPで得た(TC付きの)応答を
      // そのまま使う(何も返さないよりはマシ、というBIND等と同じ扱い)。
    }

    if ((size_t)got > max_res_len) {
      size_t copy_len = max_res_len;
      memcpy(res, s_forward_res_buf, copy_len);
      res[0] = req[0]; res[1] = req[1];
      res[2] |= 0x82; // QR=1, TC=1
      res[4] = req[4]; res[5] = req[5];
      res[6] = 0; res[7] = 0;
      res[8] = 0; res[9] = 0;
      res[10] = 0; res[11] = 0;
      uint16_t qdcount = (req[4] << 8) | req[5];
      size_t qlen = get_question_end_offset(res, copy_len, qdcount);
      if (qlen < DNS_HEADER_SIZE || qlen > copy_len) {
        size_t req_qlen = get_question_end_offset(req, req_len, qdcount);
        if (req_qlen >= DNS_HEADER_SIZE && req_qlen <= max_res_len) {
          memcpy(res + DNS_HEADER_SIZE, req + DNS_HEADER_SIZE, req_qlen - DNS_HEADER_SIZE);
          qlen = req_qlen;
        } else {
          qlen = DNS_HEADER_SIZE;
        }
      }
      return (int)qlen;
    }

    size_t copy_len = (size_t)got;
    memcpy(res, s_forward_res_buf, copy_len);
    res[0] = req[0]; res[1] = req[1]; // クライアントの元のトランザクションIDへ復元
    return (int)copy_len;
  }

  syslog(LOG_ERR, "[Forward] zone '%s': all %d forwarder(s) failed or timed out", zcfg->domain, zcfg->forwarders_count);
  return build_synthetic_servfail(req, req_len, res, max_res_len);
}

bool spawn_one_program_plugin(zone_config_t *zcfg, program_plugin_t *out) {
  if (!zcfg->program_path) {
    syslog(LOG_ERR, "[Plugin] zone '%s' program_path is NULL; refusing to spawn", zcfg->domain);
    return false;
  }

  int in_pipe[2];  // parent(karidns) write -> child(script) stdin
  int out_pipe[2]; // child(script) stdout -> parent(karidns) read
  if (pipe(in_pipe) != 0 || pipe(out_pipe) != 0) {
    syslog(LOG_ERR, "[Plugin] pipe() failed for zone '%s': %m", zcfg->domain);
    return false;
  }

  pid_t pid = fork();
  if (pid < 0) {
    syslog(LOG_ERR, "[Plugin] fork() failed for zone '%s': %m", zcfg->domain);
    close(in_pipe[0]); close(in_pipe[1]); close(out_pipe[0]); close(out_pipe[1]);
    return false;
  }

  if (pid == 0) {
    dup2(in_pipe[0], STDIN_FILENO);
    dup2(out_pipe[1], STDOUT_FILENO);
    close(in_pipe[0]); close(in_pipe[1]);
    close(out_pipe[0]); close(out_pipe[1]);

#ifdef __FreeBSD__
    closefrom(STDERR_FILENO + 1); // 継承済みの全fd(制御チャネル/IPC/リスニングソケット等)を確実に閉じる
#else
    int maxfd = (int)sysconf(_SC_OPEN_MAX);
    if (maxfd < 0) maxfd = 1024;
    for (int fd = 3; fd < maxfd; fd++) {
      close(fd);
    }
#endif

    // H-1適用に伴う必須フェイルセーフ:
    // program-user未設定のままrootでexecされることを、main()の
    // 「root起動でuser/group未設定なら拒否する」既存ポリシーと同様に禁止する。
    if (!zcfg->program_user && geteuid() == 0) {
      // 標準エラーはまだ生きている(closefromはSTDERR_FILENO+1から)ので出力可能
      fprintf(stderr, "[FATAL] Zone '%s': 'program-user' is not set and karidns is running "
              "as root; refusing to exec plugin as root.\n", zcfg->domain);
      _exit(125);
    }

    if (zcfg->program_user) {
      struct passwd *pwd = getpwnam(zcfg->program_user);
      if (!pwd) { _exit(126); }
      if (setgroups(0, NULL) != 0) _exit(126);
      if (setgid(pwd->pw_gid) != 0) _exit(126);
      if (setuid(pwd->pw_uid) != 0) _exit(126);
    }

    char *argv[64];
    int ai = 0;
    argv[ai++] = (char *)zcfg->program_path;
    for (int i = 0; i < zcfg->program_args_count && ai < 63; i++)
      argv[ai++] = zcfg->program_args[i];
    argv[ai] = NULL;

    execv(zcfg->program_path, argv);
    _exit(127);
  }

  close(in_pipe[0]);
  close(out_pipe[1]);

  fcntl(in_pipe[1], F_SETFD, FD_CLOEXEC);
  fcntl(out_pipe[0], F_SETFD, FD_CLOEXEC);
#ifdef __FreeBSD__
  cap_rights_t rights;
  cap_rights_init(&rights, CAP_WRITE, CAP_EVENT, CAP_FCNTL);
  cap_rights_limit(in_pipe[1], &rights);
  cap_rights_t rights_r;
  cap_rights_init(&rights_r, CAP_READ, CAP_EVENT, CAP_FCNTL);
  cap_rights_limit(out_pipe[0], &rights_r);
#endif

  strncpy(out->domain, zcfg->domain, sizeof(out->domain) - 1);
  out->domain[sizeof(out->domain) - 1] = '\0';
  out->pid = pid;
  out->stdin_fd = in_pipe[1];
  out->stdout_fd = out_pipe[0];
  pthread_mutex_init(&out->lock, NULL);
  out->timeout_ms = zcfg->program_timeout_ms > 0 ? zcfg->program_timeout_ms : 2000;
  out->max_failures = zcfg->program_max_failures > 0 ? zcfg->program_max_failures : 5;
  out->disable_auto_tc_flag = zcfg->disable_auto_tc_flag;
  compute_program_zone_fingerprint(zcfg, out->config_fingerprint, sizeof(out->config_fingerprint));
  atomic_init(&out->consecutive_failures, 0);
  atomic_init(&out->dead, false);

  syslog(LOG_INFO, "[Plugin] Spawned program zone '%s' -> pid=%d exec='%s'",
         zcfg->domain, pid, zcfg->program_path);
  return true;
}

void spawn_program_zone_plugins(server_config_t *cfg) {
  int count = 0;
  for (view_config_t *v = cfg->views; v; v = v->next)
    for (zone_config_t *z = v->zones; z; z = z->next)
      if (z->type && strcasecmp(z->type, "program") == 0) count++;

  if (count == 0) return;

  if (!cfg->allow_program_zones) {
    syslog(LOG_CRIT, "[Plugin] %d zone(s) with type \"program\" found but "
           "allow-program-zones is not set to yes in options{}. Refusing to start.", count);
    fprintf(stderr, "[FATAL] type \"program\" zones require "
            "'allow-program-zones yes;' in options{}.\n");
    exit(EXIT_FAILURE);
  }

  syslog(LOG_WARNING, "[Plugin] %d program zone(s) enabled. "
         "This is a TEST-ONLY feature; do not use in production.", count);

  g_program_plugins = calloc(count, sizeof(program_plugin_t));
  if (!g_program_plugins) exit(EXIT_FAILURE);

  int idx = 0;
  for (view_config_t *v = cfg->views; v; v = v->next) {
    for (zone_config_t *z = v->zones; z; z = z->next) {
      if (!z->type || strcasecmp(z->type, "program") != 0) continue;
      if (!z->program_path) {
        syslog(LOG_ERR, "[Plugin] zone '%s' has type program but no 'program' path set; skipping (will SERVFAIL)", z->domain);
        continue;
      }
      if (!z->program_user && cfg->user) {
        z->program_user = strdup(cfg->user);
      }
      if (spawn_one_program_plugin(z, &g_program_plugins[idx])) idx++;
    }
  }
  g_program_plugins_count = idx;
}

view_snapshot_t *select_view(zone_db_snapshot_t *snap, const char *client_ip) {
  if (!snap) return NULL;
  for (size_t i = 0; i < snap->view_count; i++) {
    if (snap->views[i].match_clients_parsed && snap->views[i].match_clients_count > 0) {
      if (check_acl_bin(client_ip, snap->views[i].match_clients_parsed, snap->views[i].match_clients_count)) {
        return &snap->views[i];
      }
    } else if (snap->views[i].match_clients && snap->views[i].match_clients_count > 0) {
      if (check_acl(client_ip, snap->views[i].match_clients, snap->views[i].match_clients_count)) {
        return &snap->views[i];
      }
    } else {
      return &snap->views[i];
    }
  }
  return NULL;
}

void build_zone_response_cache(zone_arena_t *arena, server_config_t *cfg, const char *domain) {
  if (!arena || arena->count == 0) return;

  // If per-client location/ECS features or tinydns format are active, skip static wire cache
  if (arena->is_tinydns_format) return;
  if (arena->locations != NULL && arena->location_count > 0) return;
  if (arena->bind_location_tags != NULL && arena->bind_location_tag_count > 0) return;
  if (arena->bind_ecs_tags != NULL && arena->bind_ecs_tag_count > 0) return;

  if (cfg && cfg->wire_cache_max_records > 0 && arena->count > cfg->wire_cache_max_records) {
    syslog(LOG_NOTICE,
           "[WireCache] zone '%s' has %zu records, exceeding wire-cache-max-records=%u; caching disabled for this zone",
           domain ? domain : "(unknown)", arena->count, cfg->wire_cache_max_records);
    return;
  }

  zone_config_t *zcfg = cfg ? find_zone_config_in_view(cfg, NULL, domain) : NULL;
  if (zcfg) {
    if (zcfg->location_tags != NULL && zcfg->location_tag_count > 0) return;
    if (zcfg->ecs_tags != NULL && zcfg->ecs_tag_count > 0) return;
    if (zcfg->type && strcasecmp(zcfg->type, "master") != 0 && strcasecmp(zcfg->type, "primary") != 0 &&
        strcasecmp(zcfg->type, "slave") != 0 && strcasecmp(zcfg->type, "secondary") != 0) return;
  }
  if (cfg) {
    if (cfg->location_tags != NULL && cfg->location_tag_count > 0) return;
    if (cfg->ecs_tags != NULL && cfg->ecs_tag_count > 0) return;
  }

  free_zone_response_cache(arena);

  size_t bucket_count = 16;
  while (bucket_count < arena->count * 2) {
    bucket_count <<= 1;
    if (bucket_count >= 65536) break;
  }

  arena->response_cache.buckets = calloc(bucket_count, sizeof(response_cache_entry_t *));
  if (!arena->response_cache.buckets) return;
  arena->response_cache.bucket_count = bucket_count;
  arena->response_cache.entry_count = 0;

  bool minimal_responses = cfg ? cfg->minimal_responses : false;
  bool minimal_any = cfg ? cfg->minimal_any : false;
  uint32_t minimal_any_ttl = cfg ? cfg->minimal_any_ttl : 86400;

  size_t cached_entries = 0;
  size_t cached_bytes = 0;

  for (size_t i = 0; i < arena->count; i++) {
    dns_record_t *rec = &arena->records[i];
    if (!rec->name || rec->name[0] == '\0') continue;
    if (rec->name[0] == '*' && (rec->name[1] == '.' || rec->name[1] == '\0')) continue;

    uint16_t qtype = rec->type_code;
    if (is_non_data_rrtype(qtype)) continue;
    if (qtype == 46 || qtype == 47 || qtype == 50) continue; // RRSIG, NSEC, NSEC3

    uint16_t qclass = rec->class_val ? rec->class_val : 1;
    if (qclass != 1) continue;

    const char *qname = rec->name;
    uint32_t name_hash = calc_fnv1a_str(qname);

    // Skip caching if any record for this qname is location-tagged, ECS-tagged, or time-sensitive
    bool has_dynamic_record = false;
    if (arena->hash_size > 0 && arena->hash_table) {
      size_t name_idx = name_hash & (arena->hash_size - 1);
      for (int r_idx = arena->hash_table[name_idx]; r_idx != -1; r_idx = arena->records[r_idx].next_record) {
        dns_record_t *r = &arena->records[r_idx];
        if (strcasecmp(r->name, qname) == 0) {
          if (r->bind_location_tag != NULL || r->ecs_subnet_tag != NULL ||
              r->tinydns_loc[0] != 0 || r->tinydns_ttd != 0 || r->tinydns_ttl_countdown) {
            has_dynamic_record = true;
            break;
          }
        }
      }
    }
    if (has_dynamic_record) continue;
    size_t hash_idx = (name_hash ^ (uint32_t)qtype) & (bucket_count - 1);

    bool already_cached = false;
    for (response_cache_entry_t *e = arena->response_cache.buckets[hash_idx]; e != NULL; e = e->next) {
      if (e->qtype == qtype && e->qclass == qclass && e->name_hash == name_hash &&
          strcasecmp(e->name, qname) == 0) {
        already_cached = true;
        break;
      }
    }
    if (already_cached) continue;

    uint8_t dummy_res[4096];
    memset(dummy_res, 0, DNS_HEADER_SIZE);

    long wlen = write_uncompressed_name(dummy_res, DNS_HEADER_SIZE, sizeof(dummy_res), qname);
    if (wlen <= 0) continue;
    uint16_t q_offset = (uint16_t)(DNS_HEADER_SIZE + wlen);
    if (q_offset + 4 > sizeof(dummy_res)) continue;
    dummy_res[q_offset] = (uint8_t)(qtype >> 8);
    dummy_res[q_offset + 1] = (uint8_t)(qtype & 0xFF);
    dummy_res[q_offset + 2] = (uint8_t)(qclass >> 8);
    dummy_res[q_offset + 3] = (uint8_t)(qclass & 0xFF);
    q_offset += 4;

    uint16_t offset = q_offset;
    uint16_t ancount = 0, nscount = 0, arcount = 0;

    compress_ctx_t comp_ctx;
    memset(&comp_ctx, 0, sizeof(comp_ctx));
    compress_ctx_init_packet(&comp_ctx);
    register_wire_name_for_compression(dummy_res, DNS_HEADER_SIZE, &comp_ctx);

    zone_db_entry_t dummy_entry;
    memset(&dummy_entry, 0, sizeof(dummy_entry));
    if (domain) {
      strncpy(dummy_entry.domain, domain, sizeof(dummy_entry.domain) - 1);
    }
    zone_db_entry_t *db_entry_ptr = &dummy_entry;
    zone_arena_t *current_zone_ptr = arena;

    uint16_t qtypes_arr[1] = { qtype };
    dummy_res[2] = 0x84; // QR=1, AA=1
    dummy_res[3] = 0x00; // NOERROR

    resolve_name(qname, qclass, qtypes_arr, 1,
                 &db_entry_ptr, &current_zone_ptr,
                 dummy_res, sizeof(dummy_res),
                 &offset, &comp_ctx, &ancount, &nscount, &arcount,
                 minimal_responses, minimal_any, minimal_any_ttl,
                 false /* dnssec_ok */, NULL /* view */, NULL /* qtx_included */,
                 NULL /* client_ip */, cfg, false /* ecs_trusted */,
                 NULL, 0, 0, NULL);

    uint8_t rcode = dummy_res[3] & 0x0F;
    bool tc = (dummy_res[2] & 0x02) != 0;

    if (rcode == 0 && !tc && ancount > 0 && offset <= UDP_DEFAULT_MAX_RES_LEN && offset > q_offset) {
      uint16_t body_len = offset - q_offset;
      uint8_t *body = (uint8_t *)arena_alloc(arena, body_len);
      if (!body) continue;
      memcpy(body, dummy_res + q_offset, body_len);

      char *cached_name = arena_strdup(arena, qname);
      if (!cached_name) continue;

      response_cache_entry_t *entry = (response_cache_entry_t *)arena_alloc(arena, sizeof(response_cache_entry_t));
      if (!entry) continue;

      entry->name = cached_name;
      entry->name_hash = name_hash;
      entry->qtype = qtype;
      entry->qclass = qclass;
      entry->ancount = ancount;
      entry->nscount = nscount;
      entry->arcount = arcount;
      entry->body_len = body_len;
      entry->body = body;
      entry->next = arena->response_cache.buckets[hash_idx];
      arena->response_cache.buckets[hash_idx] = entry;
      arena->response_cache.entry_count++;

      cached_entries++;
      cached_bytes += body_len + strlen(cached_name) + 1 + sizeof(response_cache_entry_t);
    }
  }

  if (cached_entries > 0) {
    arena->response_cache.total_bytes = cached_bytes;
    syslog(LOG_NOTICE,
           "[WireCache] zone '%s': cached %zu entries (~%zu bytes) out of %zu total records",
           domain ? domain : "(unknown)", cached_entries, cached_bytes, arena->count);
  }
}


int process_dns_query_impl(const uint8_t *req, size_t req_len, uint8_t *res,
                            size_t max_res_len, const char *qname, uint16_t qtype,
                            const char *client_ip, compress_ctx_t *comp_ctx,
                            bool is_tcp, rate_limit_config_t **out_rrl_cfg,
                            zone_db_snapshot_t *snap, server_config_t *cfg,
                            zone_db_entry_t **out_matched_entry) {
  if (req_len < DNS_HEADER_SIZE) {
    return 0; // 不正な短いパケットは無応答で破棄
  }

  uint8_t tsig_mac[64]; /* >= EVP_MAX_MD_SIZE */
  static_assert(sizeof(tsig_mac) >= 64, "tsig_mac must be >= EVP_MAX_MD_SIZE (64)");
  size_t tsig_mac_len = 0;
  char current_qname[256];
  strlcpy(current_qname, qname, sizeof(current_qname));
  char current_qname_lc[256];
  size_t current_qname_lc_len = 0;
  for (; current_qname[current_qname_lc_len] != '\0' && current_qname_lc_len < sizeof(current_qname_lc) - 1; current_qname_lc_len++) {
    char c = current_qname[current_qname_lc_len];
    current_qname_lc[current_qname_lc_len] = (c >= 'A' && c <= 'Z') ? (c | 0x20) : c;
  }
  current_qname_lc[current_qname_lc_len] = '\0';
  zone_arena_t *current_zone = NULL;
  zone_db_entry_t *db_entry = NULL;
  view_snapshot_t *view = NULL;

  if (snap) {
    view = select_view(snap, client_ip);
    if (view) {
      db_entry = find_zone_in_view(view, current_qname);
    }
  }

  zone_config_t *matched_zcfg = (db_entry && view && cfg)
      ? find_zone_config_in_view(cfg, view->name, db_entry->domain)
      : NULL;
  if (out_rrl_cfg) {
    *out_rrl_cfg = cfg ? &cfg->rrl : NULL;
    if (matched_zcfg && matched_zcfg->rrl.configured) {
      *out_rrl_cfg = &matched_zcfg->rrl;
    }
  }
  
  uint16_t qdcount = (req[4] << 8) | req[5],
           ancount_req = (req[6] << 8) | req[7],
           nscount_req = (req[8] << 8) | req[9],
           arcount_req = (req[10] << 8) | req[11];

  edns_info_t edns;
  memset(&edns, 0, sizeof(edns));
  edns.present = false;
  if (parse_edns_opt(req, req_len, qdcount, ancount_req, nscount_req, arcount_req, &edns) < 0 || edns.has_malformed_cookie) {
    memcpy(res, req, DNS_HEADER_SIZE);
    res[2] |= 0x80;
    res[3] = (res[3] & 0xF0) | 0x01; // FORMERR
    memset(&res[4], 0, 8); // qdcount, ancount, nscount, arcount = 0
    return DNS_HEADER_SIZE;
  }
  edns.ede_count = 0; // 反射防止
  if (edns.present && edns.udp_payload_size < 512) {
    edns.udp_payload_size = 512;
  }
  /* udp-bufsize / zone-udp-bufsize: UDP 応答サイズの上限であり、OPT で通知する値。
   * 範囲はパーサで 512..4096 に制限済み (呼び出し側の UDP 応答バッファは >= 4096)。 */
  if (matched_zcfg && matched_zcfg->zone_udp_bufsize > 0)
    edns.server_udp_size = matched_zcfg->zone_udp_bufsize;
  else if (cfg && cfg->udp_bufsize > 0)
    edns.server_udp_size = cfg->udp_bufsize;

  if (out_matched_entry) *out_matched_entry = db_entry;
  if (db_entry) {
    atomic_fetch_add_explicit(&db_entry->observatory.queries_total, 1, memory_order_relaxed);
    if (is_tcp) {
      atomic_fetch_add_explicit(&db_entry->observatory.tcp_queries, 1, memory_order_relaxed);
    }
    if (edns.present) {
      atomic_fetch_add_explicit(&db_entry->observatory.edns_queries, 1, memory_order_relaxed);
      if (edns.dnssec_ok) {
        atomic_fetch_add_explicit(&db_entry->observatory.dnssec_do_queries, 1, memory_order_relaxed);
      }
      if (edns.has_ecs) {
        atomic_fetch_add_explicit(&db_entry->observatory.ecs_queries, 1, memory_order_relaxed);
      }
    }
  }

  server_config_t *cfg_for_ede = cfg;
  bool send_ede = (cfg_for_ede != NULL && cfg_for_ede->send_extended_errors);
  
  if (!cfg_for_ede || !cfg_for_ede->rfc10029_mqtype_enable) {
    edns.has_mqtype_query = false;
    edns.saw_invalid_mqtype_response_in_query = false;
    edns.mqtype_query_duplicated = false;
    edns.mqtype_count = 0;
  }

  if (edns.saw_invalid_mqtype_response_in_query || edns.mqtype_query_duplicated) {
    memcpy(res, req, DNS_HEADER_SIZE);
    res[2] |= 0x80;
    res[3] = (res[3] & 0xF0) | 1; // FORMERR
    res[6] = 0; res[7] = 0; res[8] = 0; res[9] = 0;
    uint16_t offset = DNS_HEADER_SIZE;
    uint16_t arcount = 0;
    if (edns.present) assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, 0, is_tcp, cfg);
    res[10] = arcount >> 8; res[11] = arcount & 0xFF;
    return offset;
  }

  if (edns.present && edns.version > 0) {
    size_t copy_len = req_len > max_res_len ? max_res_len : req_len;
    memcpy(res, req, copy_len);
    res[2] |= 0x80; // QR=1
    res[3] &= 0xF0; // RCODE=0 (Base RCODE)
    
    // 質問セクション以降をクリア
    res[6] = 0; res[7] = 0; // ANCOUNT=0
    res[8] = 0; res[9] = 0; // NSCOUNT=0
    
    uint16_t offset = (uint16_t)get_question_end_offset(res, copy_len, qdcount);
    uint16_t arcount = 0;
    
    // RFC 6891: 応答にはサーバーがサポートする最大のバージョン(0)をセットする
    edns.version = 0;
    
    // rcode_ext = 1 (1 << 4 | Base 0 = 16 = BADVERS)
    assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, 1, is_tcp, cfg);
    res[10] = arcount >> 8;
    res[11] = arcount & 0xFF;
    return offset;
  }

  uint8_t opcode = (req[2] >> 3) & 0x0F;
  if (opcode != 0 && opcode != 4 && opcode != 5) {
    size_t copy_len = req_len > max_res_len ? max_res_len : req_len;
    memcpy(res, req, copy_len);
    res[2] |= 0x80;
    res[3] = (res[3] & 0xF0) | 0x04; // NOTIMP
    add_ede(&edns, send_ede, 21, "This opcode is not supported by this server");
    
    uint16_t offset = (uint16_t)get_question_end_offset(res, copy_len, qdcount);
    res[6] = 0; res[7] = 0; // ANCOUNT = 0
    res[8] = 0; res[9] = 0; // NSCOUNT = 0
    uint16_t arcount = 0;
    if (edns.present) {
      assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, 0, is_tcp, cfg);
    }
    res[10] = arcount >> 8;
    res[11] = arcount & 0xFF;
    return offset;
  }

  // RFC 9619: OPCODE=0(QUERY) allows QDCOUNT 0 or 1; only QDCOUNT>1 is FORMERR.
  // OPCODE=4(NOTIFY)/5(UPDATE) still require QDCOUNT==1.
  bool qdcount_invalid = (opcode == 0) ? (qdcount > 1) : (qdcount != 1);
  if (qdcount_invalid) {
    size_t copy_len = req_len > max_res_len ? max_res_len : req_len;
    memcpy(res, req, copy_len);
    res[2] |= 0x80;
    res[3] = (res[3] & 0xF0) | 0x01; // FORMERR
    add_ede(&edns, send_ede, 0, NULL);
    uint16_t offset = (uint16_t)get_question_end_offset(res, copy_len, qdcount);
    res[6] = 0; res[7] = 0; // ANCOUNT = 0
    res[8] = 0; res[9] = 0; // NSCOUNT = 0
    uint16_t arcount = 0;
    if (edns.present) {
      assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, 0, is_tcp, cfg);
    }
    res[10] = arcount >> 8;
    res[11] = arcount & 0xFF;
    return offset;
  }

  // RFC 9619: QDCOUNT=0 QUERY – no question section, return minimal response.
  if (opcode == 0 && qdcount == 0) {
    if (edns.has_mqtype_query) {
      // RFC 10029 §3.3: MQTYPE-Query option in a query with QDCOUNT=0 MUST be FORMERR.
      memcpy(res, req, DNS_HEADER_SIZE);
      res[2] |= 0x80;                      // QR=1
      res[3] = (res[3] & 0xF0) | 1;        // FORMERR
      res[6] = 0; res[7] = 0;              // ANCOUNT=0
      res[8] = 0; res[9] = 0;              // NSCOUNT=0
      res[10] = 0; res[11] = 0;            // ARCOUNT=0 (OPT自体は付けない。他のopcode==4/5分岐と挙動を合わせる)
      return DNS_HEADER_SIZE;
    }
    size_t copy_len = req_len > max_res_len ? max_res_len : req_len;
    memcpy(res, req, copy_len);
    res[2] |= 0x80; // QR=1
    res[3] &= 0xF0; // NOERROR
    res[6] = 0; res[7] = 0; // ANCOUNT=0
    res[8] = 0; res[9] = 0; // NSCOUNT=0
    uint16_t offset0 = DNS_HEADER_SIZE;
    uint16_t arcount0 = 0;
    if (edns.present) {
      if (edns.has_cookie) {
        // Refresh server cookie for cookie-only probes (RFC 7873 §5.4)
        if (!generate_server_cookie(cfg, client_ip, edns.client_cookie, edns.server_cookie, (uint32_t)time(NULL))) {
            edns.server_cookie_len = 0;
            edns.has_cookie = false;
        } else {
            edns.server_cookie_len = 16;
        }
      }
      assemble_edns_opt(res, max_res_len, &offset0, &arcount0, &edns, 0, is_tcp, cfg);
    }
    res[10] = arcount0 >> 8;
    res[11] = arcount0 & 0xFF;
    return offset0;
  }

  if (opcode == 4) { // NOTIFY
    if (db_entry && view) {
      server_config_t *cfg_chk = cfg;
      zone_config_t *zc = find_zone_config_in_view(cfg_chk, view->name, db_entry->domain);
      if (zc && zc->type && (strcasecmp(zc->type, "program") == 0 ||
                              strcasecmp(zc->type, "forward") == 0)) {
        size_t copy_len = req_len > max_res_len ? max_res_len : req_len;
        memcpy(res, req, copy_len);
        res[2] |= 0x80; res[2] &= ~0x01; res[3] = (res[3] & 0xF0) | 0x04; // NOTIMP
        res[6] = 0; res[7] = 0; res[8] = 0; res[9] = 0; res[10] = 0; res[11] = 0;
        return copy_len;
      }
    }
    if (edns.has_mqtype_query) {
      memcpy(res, req, DNS_HEADER_SIZE);
      res[2] |= 0x80; res[2] &= ~0x01; res[3] = (res[3] & 0xF0) | 1;
      res[6] = 0; res[7] = 0; res[8] = 0; res[9] = 0; res[10] = 0; res[11] = 0;
      return DNS_HEADER_SIZE;
    }
    bool has_tsig = packet_has_tsig(req, req_len);
    bool auth = false;
    tsig_key_t *matched_key = NULL;
    tsig_key_t *attempted_key = NULL;
    int tsig_error_code = 0;
    
    if (db_entry && view) {
      zone_config_t *zcfg = find_zone_config_in_view(cfg, view->name, db_entry->domain);
      if (zcfg && zcfg->masters_count > 0) {
        for (int k = 0; k < zcfg->masters_count; k++) {
          if (zcfg->masters_parsed ? cidr_entry_match_str(&zcfg->masters_parsed[k], client_ip)
                                   : match_cidr(client_ip, zcfg->masters[k].ip)) {
            auth = true;
            break;
          }
        }
        if (zcfg->tsig_key && zcfg->tsig_key[0] != '\0') {
          tsig_key_t *k = cfg ? cfg->keys : NULL;
          while (k) {
            if (strcmp(k->name, zcfg->tsig_key) == 0) {
              matched_key = k;
              break;
            }
            k = k->next;
          }
          if (!matched_key) {
            auth = false;
          } else {
            attempted_key = matched_key;
            int err = tsig_verify_packet(req, req_len, matched_key, NULL, 0, NULL, 0, false, tsig_mac, &tsig_mac_len);
            if (err != 0) {
              auth = false;
              tsig_error_code = err > 0 ? err : 16;
              matched_key = NULL;
            }
          }
        }
      }
    }
    // RFC 2845 / RFC 8945 §5.4: If packet has TSIG, MUST NOT accept based solely on IP match if TSIG verification failed
    if (has_tsig && (!matched_key || tsig_error_code != 0)) {
      auth = false;
      if (!attempted_key) {
        tsig_key_t *k = cfg ? cfg->keys : NULL;
        while (k) {
          int err = tsig_verify_packet(req, req_len, k, NULL, 0, NULL, 0, false, tsig_mac, &tsig_mac_len);
          if (err == 0) {
            attempted_key = k;
            tsig_error_code = 9; // key known but not allowed on zone
            break;
          }
          k = k->next;
        }
        if (!attempted_key) {
          tsig_error_code = 17; // BADKEY
        }
      }
    }
      
    size_t copy_len = req_len > max_res_len ? max_res_len : req_len;
    memcpy(res, req, copy_len);
    res[2] |= 0x84; // QR=1, AA=1
    res[2] &= ~0x01; // RD=0 per RFC 1996 §3.7
    
    if (auth) {
      res[3] &= 0xF0;
      atomic_store_explicit(&db_entry->refresh_now, true, memory_order_release);
      if (g_control_kq != -1) {
        struct kevent ev;
        EV_SET(&ev, 2, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
        kevent(g_control_kq, &ev, 1, NULL, 0, NULL);
      }
    } else {
      if (attempted_key || has_tsig) {
          res[3] = (res[3] & 0xF0) | 9; // NOTAUTH
          add_ede(&edns, send_ede, 18, "Invalid TSIG");
      } else {
          res[3] = (res[3] & 0xF0) | 5; // REFUSED
          add_ede(&edns, send_ede, 18, "Query refused due to access control");
      }
    }
    uint16_t offset = (uint16_t)get_question_end_offset(res, copy_len, qdcount);
    res[6] = 0; res[7] = 0; // ANCOUNT = 0
    res[8] = 0; res[9] = 0; // NSCOUNT = 0
    uint16_t arcount = 0;
    if (edns.present) {
      assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, 0, is_tcp, cfg);
    }
    res[10] = arcount >> 8;
    res[11] = arcount & 0xFF;
    
    tsig_key_t *sign_key = auth ? matched_key : attempted_key;
    if (sign_key) {
      size_t sign_len = offset;
      if (tsig_sign_packet(res, &sign_len, max_res_len, sign_key, auth ? 0 : tsig_error_code, tsig_mac, &tsig_mac_len, NULL, 0, false) == 0) {
        offset = sign_len;
      } else {
        res[3] = (res[3] & 0xF0) | 0x02; // SERVFAIL
        res[10] = 0; res[11] = 0; // ARCOUNT = 0
        offset = (uint16_t)get_question_end_offset(res, copy_len, qdcount);
      }
    }
    return offset;
  }

  if (opcode == 5) { // UPDATE
    if (db_entry && view) {
      server_config_t *cfg_chk = cfg;
      zone_config_t *zc = find_zone_config_in_view(cfg_chk, view->name, db_entry->domain);
      if (zc && zc->type && (strcasecmp(zc->type, "program") == 0 ||
                              strcasecmp(zc->type, "forward") == 0)) {
        size_t copy_len = req_len > max_res_len ? max_res_len : req_len;
        memcpy(res, req, copy_len);
        res[2] |= 0x80; res[2] &= ~0x01; res[3] = (res[3] & 0xF0) | 0x04; // NOTIMP
        res[6] = 0; res[7] = 0; res[8] = 0; res[9] = 0; res[10] = 0; res[11] = 0;
        return copy_len;
      }
    }
    if (edns.has_mqtype_query) {
      memcpy(res, req, DNS_HEADER_SIZE);
      res[2] |= 0x80; res[2] &= ~0x01; res[3] = (res[3] & 0xF0) | 1;
      res[6] = 0; res[7] = 0; res[8] = 0; res[9] = 0; res[10] = 0; res[11] = 0;
      return DNS_HEADER_SIZE;
    }
    bool has_tsig = packet_has_tsig(req, req_len);
    bool auth = false;
    bool zone_is_master = false;
    tsig_key_t *matched_key = NULL;
    tsig_key_t *attempted_key = NULL;
    int tsig_error_code = 0;
    if (db_entry && view) {
      zone_config_t *zcfg = find_zone_config_in_view(cfg, view->name, db_entry->domain);
      if (zcfg) {
        if (zcfg->type && (strcasecmp(zcfg->type, "master") == 0 || strcasecmp(zcfg->type, "primary") == 0)) {
          zone_is_master = true;
        }
      }
      if (zcfg && zcfg->allow_update_count > 0) {
        if (zcfg->allow_update_parsed) {
          if (check_acl_bin(client_ip, zcfg->allow_update_parsed, zcfg->allow_update_count)) {
            auth = true;
          }
        } else if (check_acl(client_ip, zcfg->allow_update, zcfg->allow_update_count)) {
          auth = true;
        }
        tsig_key_t *k = cfg ? cfg->keys : NULL;
        while (k) {
          bool key_allowed = false;
          for (int i = 0; i < zcfg->allow_update_count; i++) {
            if (strcmp(k->name, zcfg->allow_update[i]) == 0) {
              key_allowed = true;
              break;
            }
          }
          if (key_allowed) {
            attempted_key = k;
            int err = tsig_verify_packet(req, req_len, k, NULL, 0, NULL, 0, false, tsig_mac, &tsig_mac_len);
            if (err == 0) {
              matched_key = k;
              attempted_key = k;
              tsig_error_code = 0;
              auth = true;
              break;
            } else {
              tsig_error_code = err > 0 ? err : 16;
            }
          }
          k = k->next;
        }
        if (has_tsig && !attempted_key) {
          k = cfg ? cfg->keys : NULL;
          while (k) {
            int err = tsig_verify_packet(req, req_len, k, NULL, 0, NULL, 0, false, tsig_mac, &tsig_mac_len);
            if (err == 0) {
              attempted_key = k;
              tsig_error_code = 9; // NOTAUTH (key valid but not authorized for update)
              break;
            }
            k = k->next;
          }
          if (!attempted_key) {
            tsig_error_code = 17; // BADKEY
          }
        }
      }
    }
    // RFC 2845 / RFC 8945 §5.4: If packet has TSIG, MUST NOT accept based solely on IP match if TSIG verification failed!
    if (has_tsig && (!matched_key || tsig_error_code != 0)) {
      auth = false;
    }
    
    size_t copy_len = req_len > max_res_len ? max_res_len : req_len;
    memcpy(res, req, copy_len);
    res[2] |= 0x80; // QR=1
    res[2] &= ~0x01; // RD=0 per RFC 2136 §2.2 / §3.8
    
    int rcode = 5; // REFUSED
    if (auth && zone_is_master) {
      rcode = handle_dynamic_update(req, req_len, db_entry, client_ip, matched_key ? matched_key->name : "<none>");
    } else if (auth && !zone_is_master) {
      rcode = 9; // NOTAUTH (RFC 2136 §3.8: Server is not the primary for the zone)
      add_ede(&edns, send_ede, 20, "This server is not the primary for the zone");
    } else {
      if (attempted_key || has_tsig) {
        rcode = 9; // NOTAUTH
        add_ede(&edns, send_ede, 18, "Invalid TSIG");
      } else {
        add_ede(&edns, send_ede, 18, "Query refused due to access control");
      }
    }
    
    // Some rcodes like FORMERR (1) shouldn't leak the RCODE logic into res[3] directly without properly mapping
    res[3] = (res[3] & 0xF0) | (rcode & 0x0F);
    
    uint16_t offset = (uint16_t)get_question_end_offset(res, copy_len, qdcount);
    res[6] = 0; res[7] = 0; // ANCOUNT = 0
    res[8] = 0; res[9] = 0; // NSCOUNT = 0
    uint16_t arcount = 0;
    if (edns.present) {
      assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, 0, is_tcp, cfg);
    }
    res[10] = arcount >> 8;
    res[11] = arcount & 0xFF;
    
    tsig_key_t *sign_key = auth ? matched_key : attempted_key;
    if (sign_key) {
      size_t sign_len = offset;
      if (tsig_sign_packet(res, &sign_len, max_res_len, sign_key, auth ? 0 : tsig_error_code, tsig_mac, &tsig_mac_len, NULL, 0, false) == 0) {
        offset = sign_len;
      } else {
        res[3] = (res[3] & 0xF0) | 0x02; // SERVFAIL
        res[10] = 0; res[11] = 0; // ARCOUNT = 0
        offset = (uint16_t)get_question_end_offset(res, copy_len, qdcount);
      }
    }
    return offset;
  }

  if (db_entry) {
    current_zone = atomic_load_explicit(&db_entry->rcu.active, memory_order_acquire);
  }
  compress_ctx_init_packet(comp_ctx);

  if (edns.present) {
    if (edns.udp_payload_size < 512)
      edns.udp_payload_size = 512;
    if (!is_tcp) {
      uint16_t server_udp_size = edns.server_udp_size ? edns.server_udp_size : KARIDNS_UDP_BUFSIZE_DEFAULT;
      if (edns.udp_payload_size > server_udp_size)
        edns.udp_payload_size = server_udp_size;
      /* max_res_len は呼び出し側バッファの容量上限も兼ねる。呼び出し側が
       * UDP 既定値 (512) 未満の小さなバッファを渡した場合に EDNS の
       * payload size で拡大すると res[] の範囲外へ書き込む (スタック破壊)。
       * 本番経路は常に >= 512 を渡すため挙動は変わらない。 */
      if (edns.udp_payload_size > UDP_DEFAULT_MAX_RES_LEN &&
          max_res_len >= UDP_DEFAULT_MAX_RES_LEN)
        max_res_len = edns.udp_payload_size;
    }
  }

  uint8_t ext_rcode_out = 0;
  bool is_badcookie = false;
  
  if (edns.has_cookie) {
      bool need_new_cookie = false;
      if (edns.server_cookie_len == 0) {
          need_new_cookie = true;               // client-only cookie: hand out a Server Cookie
      } else {
          // RFC 9018 §4.2-4.4: SipHash-2-4, Reserved hashed as received, RFC 1982 timestamp window
          server_cookie_status_t cst = verify_server_cookie(cfg, client_ip, edns.client_cookie,
                                                            edns.server_cookie, edns.server_cookie_len,
                                                            (uint32_t)time(NULL));
          if (cst == SERVER_COOKIE_INVALID) {
              if (!is_tcp) {
                  is_badcookie = true;
                  ext_rcode_out = 1; // BADCOOKIE = combined RCODE 23 = (ext=1 << 4) | base=7
              }
              need_new_cookie = true;
          } else if (cst == SERVER_COOKIE_VALID_REFRESH) {
              need_new_cookie = true;           // RFC 9018 §4.3: renew cookies older than 30 minutes
          }
      }
      if (need_new_cookie) {
          if (!generate_server_cookie(cfg, client_ip, edns.client_cookie, edns.server_cookie,
                                      (uint32_t)time(NULL))) {
              edns.server_cookie_len = 0;
              edns.has_cookie = false;
          } else {
              edns.server_cookie_len = SERVER_COOKIE_LEN;
          }
      }
  }

  size_t q_offset = DNS_HEADER_SIZE;
  if (skip_wire_name(req, req_len, q_offset, &q_offset) != 0) {
    return -1;
  }
  if (q_offset + 4 > req_len) {
    size_t copy_len = req_len > max_res_len ? max_res_len : req_len;
    memcpy(res, req, copy_len);
    res[2] |= 0x80;
    res[3] = (res[3] & 0xF0) | 0x01; // FORMERR
    add_ede(&edns, send_ede, 0, NULL);
    uint16_t offset = copy_len;
    uint16_t arcount = 0;
    res[6] = 0; res[7] = 0; // ANCOUNT = 0
    res[8] = 0; res[9] = 0; // NSCOUNT = 0
    if (edns.present) {
      assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, 0, is_tcp, cfg);
    }
    res[10] = arcount >> 8;
    res[11] = arcount & 0xFF;
    return offset;
  }
    if (db_entry && db_entry->expire > 0) {
        time_t last_ok = atomic_load_explicit(&db_entry->last_successful_transfer, memory_order_acquire);
        if (last_ok > 0 && (time(NULL) - last_ok) > (time_t)db_entry->expire) {
            bool serve_stale = (cfg_for_ede != NULL && cfg_for_ede->serve_stale);
            if (!serve_stale) {
                size_t copy_len = q_offset + 4 > max_res_len ? max_res_len : q_offset + 4;
                memcpy(res, req, copy_len);
                res[2] |= 0x80;
                res[3] = (res[3] & 0xF0) | 0x02; // SERVFAIL
                add_ede(&edns, send_ede, 3, "Zone expired (SOA EXPIRE exceeded)");
                uint16_t offset = copy_len;
                uint16_t arcount = 0;
                res[6] = 0; res[7] = 0; // ANCOUNT = 0
                res[8] = 0; res[9] = 0; // NSCOUNT = 0
                if (edns.present) {
                    assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, 0, is_tcp, cfg);
                }
                res[10] = arcount >> 8;
                res[11] = arcount & 0xFF;
                return offset;
            } else {
                add_ede(&edns, send_ede, 3, "Stale Answer (Zone EXPIRED)");
            }
        }
    }

    uint16_t qclass = (req[q_offset + 2] << 8) | req[q_offset + 3];

    // UDP経由(is_tcp == 0)でAXFR(252)を受信した場合はRFC 5936違反のためFORMERRを返す
    if (!is_tcp && qtype == 252) {
      size_t copy_len = q_offset + 4 > max_res_len ? max_res_len : q_offset + 4;
      memcpy(res, req, copy_len);
      res[2] |= 0x80; // QR = 1
      res[3] = (res[3] & 0xF0) | 1; // RCODE = 1 (FORMERR)
      res[4] = 0; res[5] = 1; // QDCOUNT = 1
      res[6] = 0; res[7] = 0; // ANCOUNT = 0
      res[8] = 0; res[9] = 0; // NSCOUNT = 0
      res[10] = 0; res[11] = 0; // ARCOUNT = 0
      return copy_len;
    }

    if (__builtin_expect(qclass == 1, 1)) {
      // IN class (fast path)
    } else if (qclass == 255) {
      // ANY class
    } else if (qclass == 3) {
      // CH class
    } else {
      size_t copy_len = q_offset + 4 > max_res_len ? max_res_len : q_offset + 4;
      memcpy(res, req, copy_len);
      res[2] |= 0x80;
      res[3] = (res[3] & 0xF0) | 0x05; // REFUSED
      add_ede(&edns, send_ede, 0, NULL);
      uint16_t offset = copy_len;
      uint16_t arcount = 0;
      res[6] = 0; res[7] = 0; // ANCOUNT = 0
      res[8] = 0; res[9] = 0; // NSCOUNT = 0
      if (edns.present) {
        assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, 0, is_tcp, cfg);
      }
      res[10] = arcount >> 8;
      res[11] = arcount & 0xFF;
      return offset;
    }
  q_offset += 4;
  memcpy(res, req, q_offset);
  register_wire_name_for_compression(res, DNS_HEADER_SIZE, comp_ctx);
  res[2] |= 0x84;
  res[3] &= 0xF0;
  if (db_entry && view) {
    server_config_t *cfg_lookup = cfg;
    zone_config_t *zcfg = find_zone_config_in_view(cfg_lookup, view->name, db_entry->domain);
    if (zcfg && zcfg->type && strcasecmp(zcfg->type, "program") == 0) {
      rate_limit_config_t *rrl = zcfg->rrl.configured ? &zcfg->rrl : (cfg ? &cfg->rrl : NULL);
      if (!is_tcp && rrl && rrl->configured && rrl->early_drop) {
        struct sockaddr_storage ss;
        if (resolve_ip_port_to_sockaddr(client_ip, 0, &ss) > 0) {
          if (rrl_is_client_exhausted(&ss, rrl)) {
            return 0; // スクリプトを叩かずにドロップ
          }
        }
      }
      int plugin_result_len = dispatch_to_program_zone(
          zcfg->domain, req, req_len, res, max_res_len, client_ip, is_tcp);

      // programゾーンも他ゾーンと同じRRL設定(out_rrl_cfgは関数冒頭で既に
      // このゾーン用に正しくセット済み)でレート制限を受けさせる。
      // *out_rrl_cfg = NULL による無効化は絶対に行わないこと
      // (スプーフィングされたUDPクエリでプラグイン呼び出しを無制限に
      //  誘発できてしまい、RRLの存在意義そのものが破られる)。
      return plugin_result_len;
    }
    if (zcfg && zcfg->type && strcasecmp(zcfg->type, "forward") == 0) {
      int fwd_len = dispatch_forward_zone(zcfg, req, req_len, res, max_res_len);
      return fwd_len;
    }
  }

  res[6] = 0; res[7] = 0;
  res[8] = 0; res[9] = 0;
  res[10] = 0; res[11] = 0;

  if (!current_zone) {
    res[3] = (res[3] & 0xF0) | 5;
    if (!view) {
      add_ede(&edns, send_ede, 18, "Query refused due to access control (no view matched)");
    } else {
      add_ede(&edns, send_ede, 20, "This server is not authoritative for the queried zone");
    }
    uint16_t offset = q_offset;
    uint16_t arcount = 0;
    if (edns.present) {
      assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, ext_rcode_out, is_tcp, cfg);
      res[10] = (uint8_t)(arcount >> 8);
      res[11] = (uint8_t)(arcount & 0xFF);
    }
    return offset;
  }

  if (current_zone->count == 0) {
    res[3] = (res[3] & 0xF0) | 2; // SERVFAIL
    add_ede(&edns, send_ede, 14, "Zone not ready (empty)");
    uint16_t offset = q_offset;
    uint16_t arcount = 0;
    if (edns.present) {
      assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, ext_rcode_out, is_tcp, cfg);
      res[10] = (uint8_t)(arcount >> 8);
      res[11] = (uint8_t)(arcount & 0xFF);
    }
    return offset;
  }

  uint16_t offset = q_offset, ancount = 0, nscount = 0, arcount = 0;

  if (is_badcookie) {
    res[2] &= ~0x04; // RFC 7873 §5.2.3: AA MUST be 0
    res[3] = (res[3] & 0xF0) | 0x07; // BADCOOKIE (Base RCODE 7)
    if (edns.present) {
      assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, ext_rcode_out, is_tcp, cfg);
    }
    res[6] = 0; res[7] = 0;
    res[8] = 0; res[9] = 0;
    res[10] = (uint8_t)(arcount >> 8);
    res[11] = (uint8_t)(arcount & 0xFF);
    return offset;
  }

  // UDP IXFR (RFC 1995 §4.2):
  // If client's SOA serial matches server's current serial (up-to-date), send single SOA response (NOERROR).
  // If update is needed (or diff required), set TC=1 and send current SOA to prompt client to retry over TCP.
  if (!is_tcp && qtype == 251) {
    uint32_t client_serial = 0;
    bool has_client_soa = false;
    uint16_t req_ancount = (req[6] << 8) | req[7];
    uint16_t req_nscount = (req[8] << 8) | req[9];
    size_t p = q_offset;
    size_t next_p;

    // Skip any answer records if present in the request
    for (uint16_t i = 0; i < req_ancount; i++) {
      if (skip_wire_name(req, req_len, p, &next_p) != 0) break;
      p = next_p;
      if (p + 10 > req_len) break;
      uint16_t rdlen = (req[p + 8] << 8) | req[p + 9];
      p += 10 + rdlen;
      if (p > req_len) break;
    }

    if (req_nscount > 0 && p < req_len) {
      if (skip_wire_name(req, req_len, p, &next_p) == 0) {
        p = next_p;
        if (p + 10 <= req_len) {
          uint16_t auth_type = (req[p] << 8) | req[p + 1];
          uint16_t auth_rdlen = (req[p + 8] << 8) | req[p + 9];
          p += 10;
          if (auth_type == 6 && p + auth_rdlen <= req_len) {
            size_t rp = p;
            if (skip_wire_name(req, req_len, rp, &next_p) == 0) {
              rp = next_p;
              if (skip_wire_name(req, req_len, rp, &next_p) == 0) {
                rp = next_p;
                if (rp + 4 <= p + auth_rdlen) {
                  client_serial = ((uint32_t)req[rp] << 24) |
                                  ((uint32_t)req[rp + 1] << 16) |
                                  ((uint32_t)req[rp + 2] << 8) |
                                  req[rp + 3];
                  has_client_soa = true;
                }
              }
            }
          }
        }
      }
    }

    dns_record_t *soa_rec = NULL;
    uint32_t apex_hash = calc_fnv1a_str(db_entry->domain);
    size_t apex_idx = apex_hash & (current_zone->hash_size - 1);
    for (int i = current_zone->hash_table[apex_idx]; i != -1;
         i = current_zone->records[i].next_record) {
      if (current_zone->records[i].type_code == 6 &&
          domain_names_match_ci(current_zone->records[i].name, db_entry->domain)) {
        soa_rec = &current_zone->records[i];
        break;
      }
    }
    if (!soa_rec) {
      for (size_t i = 0; i < current_zone->count; i++) {
        if (current_zone->records[i].type_code == 6 &&
            domain_names_match_ci(current_zone->records[i].name, db_entry->domain)) {
          soa_rec = &current_zone->records[i];
          break;
        }
      }
    }

    uint32_t current_serial = 0;
    if (soa_rec && soa_rec->rdata_count >= 3) {
      current_serial = strtoul(soa_rec->rdata[2], NULL, 10);
    } else {
      current_serial = atomic_load_explicit(&db_entry->serial, memory_order_relaxed);
    }

    bool is_up_to_date = (has_client_soa && client_serial == current_serial);
    if (!is_up_to_date) {
      res[2] |= 0x02; // Set TC (Truncated) bit to prompt TCP retry
    }

    if (soa_rec) {
      dns_record_t rec_copy = *soa_rec;
      if (serialize_dns_record(res, max_res_len, &offset, &rec_copy, comp_ctx, NULL, 0xFFFFFFFF) >= 0) {
        ancount = 1;
      }
    }
    res[6] = (uint8_t)(ancount >> 8);
    res[7] = (uint8_t)(ancount & 0xFF);
    res[8] = 0; res[9] = 0;
    if (edns.present) {
      assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, ext_rcode_out, is_tcp, cfg);
    }
    res[10] = (uint8_t)(arcount >> 8);
    res[11] = (uint8_t)(arcount & 0xFF);
    return offset;
  }

  // Pre-rendered wire-format response cache (Fast Path)
  // [策A] プレーンな標準EDNSクエリ（DO=0, MQTYPEなし, ECSなし等）のみ安全にキャッシュを適用し、
  // DNSSEC(DO=1)やMQTYPE、ECS等の動的機能は通常パスへフォールバックさせる。
  bool edns_safe_for_cache = (!edns.present) ||
      (edns.version == 0 &&
       !edns.dnssec_ok &&
       !edns.compact_answers_ok &&
       !edns.has_mqtype_query &&
       !edns.has_ecs &&
       !edns.has_nsid_query &&
       !edns.has_keepalive_query &&
       !edns.has_karidns_ext &&
       edns.ede_count == 0 &&
       !edns.has_cookie &&
       !edns.has_malformed_cookie);

  if (edns_safe_for_cache && !is_badcookie && opcode == 0 && qdcount == 1 && qclass == 1 &&
      current_zone && current_zone->response_cache.buckets && max_res_len >= 512) {
    uint32_t qname_hash = calc_fnv1a_str(current_qname_lc);
    size_t hash_idx = (qname_hash ^ (uint32_t)qtype) & (current_zone->response_cache.bucket_count - 1);
    bool wc_hit = false;
    for (response_cache_entry_t *e = current_zone->response_cache.buckets[hash_idx]; e != NULL; e = e->next) {
      if (e->qtype == qtype && e->qclass == qclass && e->name_hash == qname_hash &&
          strcmp(e->name, current_qname_lc) == 0) {
        if ((size_t)q_offset + e->body_len <= max_res_len) {
          memcpy(res + q_offset, e->body, e->body_len);
          uint16_t body_offset = (uint16_t)(q_offset + e->body_len);
          uint16_t arcount = e->arcount;
          if (edns.present) {
            assemble_edns_opt(res, max_res_len, &body_offset, &arcount, &edns, 0, is_tcp, cfg);
          }
          res[6] = (uint8_t)(e->ancount >> 8);
          res[7] = (uint8_t)(e->ancount & 0xFF);
          res[8] = (uint8_t)(e->nscount >> 8);
          res[9] = (uint8_t)(e->nscount & 0xFF);
          res[10] = (uint8_t)(arcount >> 8);
          res[11] = (uint8_t)(arcount & 0xFF);
          if (db_entry) atomic_fetch_add_explicit(&db_entry->observatory.wirecache_hits, 1, memory_order_relaxed);
          return body_offset;
        }
        break;
      }
    }
    if (!wc_hit && db_entry) {
      atomic_fetch_add_explicit(&db_entry->observatory.wirecache_misses, 1, memory_order_relaxed);
    }
  }

  uint16_t qtypes[17];
  int num_qtypes = 1;
  qtypes[0] = qtype;

  if (edns.has_mqtype_query) {
    if (edns.mqtype_count == 0 || is_non_data_rrtype(qtype)) {
      res[2] |= 0x80;
      res[3] = (res[3] & 0xF0) | 1; // FORMERR
      res[6] = 0; res[7] = 0;
      res[8] = 0; res[9] = 0;
      offset = q_offset;
      arcount = 0;
      if (edns.present) assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, 0, is_tcp, cfg);
      res[10] = (uint8_t)(arcount >> 8);
      res[11] = (uint8_t)(arcount & 0xFF);
      return offset;
    }
    int limit = (cfg_for_ede && cfg_for_ede->max_mqtypes > 0) ? cfg_for_ede->max_mqtypes : 4;
    for (int i = 0; i < edns.mqtype_count && num_qtypes <= limit; i++) {
       uint16_t mq = edns.mqtypes[i];
       if (is_non_data_rrtype(mq)) {
          res[2] |= 0x80;
          res[3] = (res[3] & 0xF0) | 1;
          res[6] = 0; res[7] = 0;
          res[8] = 0; res[9] = 0;
          offset = q_offset; arcount = 0;
          if (edns.present) assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, 0, is_tcp, cfg);
          res[10] = (uint8_t)(arcount >> 8);
          res[11] = (uint8_t)(arcount & 0xFF);
          return offset;
       }
       bool dup = false;
       for (int j = 0; j < num_qtypes; j++) { if (qtypes[j] == mq) { dup = true; break; } }
       if (dup) {
          res[2] |= 0x80;
          res[3] = (res[3] & 0xF0) | 1;
          res[6] = 0; res[7] = 0;
          res[8] = 0; res[9] = 0;
          offset = q_offset; arcount = 0;
          if (edns.present) assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, 0, is_tcp, cfg);
          res[10] = (uint8_t)(arcount >> 8);
          res[11] = (uint8_t)(arcount & 0xFF);
          return offset;
       }
       qtypes[num_qtypes++] = mq;
    }
    edns.mqtype_count = num_qtypes - 1;
    for (int i = 0; i < edns.mqtype_count; i++) edns.mqtypes[i] = qtypes[i+1];
  }

  uint32_t qtx_included = 0;
  zone_config_t *zcfg = (db_entry && view) ? find_zone_config_in_view(cfg, view->name, db_entry->domain) : NULL;
  bool ecs_trusted = (cfg && cfg->ecs_enable && edns.has_ecs && client_ip &&
                      is_ecs_trusted_resolver(current_zone, cfg, zcfg, client_ip));
  resolve_name(current_qname, qclass, qtypes, num_qtypes, &db_entry, &current_zone, res, max_res_len,
               &offset, comp_ctx, &ancount, &nscount, &arcount,
               cfg_for_ede ? cfg_for_ede->minimal_responses : false,
               cfg_for_ede ? cfg_for_ede->minimal_any : false,
               cfg_for_ede ? cfg_for_ede->minimal_any_ttl : 86400,
               edns.dnssec_ok, view, &qtx_included, client_ip,
               cfg, ecs_trusted, edns.ecs_addr, edns.ecs_family,
               edns.ecs_source_prefix,
               &edns.ecs_scope_prefix);

  if (edns.has_mqtype_query) {
    if (res[2] & 0x02) {
      edns.mqtype_count = 0;
    } else {
      int new_count = 0;
      for (int i = 1; i < num_qtypes; i++) {
        if (qtx_included & (1 << i)) {
          edns.mqtypes[new_count++] = qtypes[i];
        }
      }
      edns.mqtype_count = new_count;
    }
  }

  if (edns.present) {
    assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, ext_rcode_out, is_tcp, cfg);
  }

  res[6] = (uint8_t)(ancount >> 8);
  res[7] = (uint8_t)(ancount & 0xFF);
  res[8] = (uint8_t)(nscount >> 8);
  res[9] = (uint8_t)(nscount & 0xFF);
  res[10] = (uint8_t)(arcount >> 8);
  res[11] = (uint8_t)(arcount & 0xFF);
  return offset;
}

STATIC_TEST void record_observatory_response(zone_db_entry_t *entry, uint8_t rcode, uint16_t ancount) {
    if (!entry) return;
    if (rcode == 0) {
        if (ancount == 0) {
            atomic_fetch_add_explicit(&entry->observatory.responses_nodata, 1, memory_order_relaxed);
        } else {
            atomic_fetch_add_explicit(&entry->observatory.responses_noerror, 1, memory_order_relaxed);
        }
    } else if (rcode == 3) {
        atomic_fetch_add_explicit(&entry->observatory.responses_nxdomain, 1, memory_order_relaxed);
    } else if (rcode == 2) {
        atomic_fetch_add_explicit(&entry->observatory.responses_servfail, 1, memory_order_relaxed);
    } else if (rcode == 5) {
        atomic_fetch_add_explicit(&entry->observatory.responses_refused, 1, memory_order_relaxed);
    }
}

int process_dns_query(const uint8_t *req, size_t req_len, uint8_t *res,
                      size_t max_res_len, const char *qname, uint16_t qtype,
                      const char *client_ip, compress_ctx_t *comp_ctx,
                      bool is_tcp, rate_limit_config_t **out_rrl_cfg,
                      zone_db_snapshot_t *snap) {
  server_config_t *cfg = acquire_config_snapshot();
  zone_db_entry_t *matched_entry = NULL;
  int ret = process_dns_query_impl(req, req_len, res, max_res_len, qname, qtype,
                                   client_ip, comp_ctx, is_tcp, out_rrl_cfg, snap, cfg, &matched_entry);
  release_config_snapshot(cfg);
  if (ret >= DNS_HEADER_SIZE && matched_entry) {
    uint8_t rcode = res[3] & 0x0F;
    uint16_t ancount = ((uint16_t)res[6] << 8) | (uint16_t)res[7];
    record_observatory_response(matched_entry, rcode, ancount);
  }
  return ret;
}

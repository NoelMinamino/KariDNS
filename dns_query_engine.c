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

/* R-31: NSEC3 parameters chosen for the zone by build_zone_index() (select_nsec3_params(): Flags 0, SHA-1, salt of
 * 0-255 octets, complete chain first; RFC 5155 §4.1.2, §7.3). NULL when the zone has no usable NSEC3PARAM at
 * apex_name: the zone then gives NSEC proofs (or none). The salt is decoded once, not per query. */
static const nsec3_params_t *zone_nsec3(const zone_arena_t *zone, const char *apex_name) {
  const nsec3_params_t *p = &zone->nsec3_active;
  return (p->param && domain_names_match_ci(p->param->name, apex_name)) ? p : NULL;
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

/* 応答に載せるレコードの絞り込み条件 (tinydns の location / 時刻、ECS / location タグ)。answer_scope が
 * NULL でなければ、見たレコードごとに note_ecs_variant() で ECS SCOPE を記録する (Answer セクション用)。 */
typedef struct {
  const char *client_loc;     /* char[2] */
  const char *client_ecs_tag;
  const char *client_loc_tag;
  uint8_t zone_scope;
  uint8_t *answer_scope;
} rr_filter_t;

/* Additional セクションに載せる名前 (MX/SRV/NS のターゲット) */
typedef struct {
  const char *targets[16];
  int count;
  bool minimal;
} glue_list_t;

enum { RRSIG_NONE, RRSIG_REQUIRED, RRSIG_OPTIONAL };

static inline void note_ecs_variant(const dns_record_t *rec, uint16_t qtype, uint8_t zone_scope,
                                    uint8_t *answer_scope);

/* O-16 / R-03: 1 つの RRset (owner と type が同じレコード全部) を書き、続けてその RRSIG を書く。
 * RRset のレコードは隣り合わせにし、RRSIG を途中に挟まない (RFC 2181 §5、BIND/Unbound と同じ並び)。
 * idxs[] は owner が入っているハッシュバケット (ルートの有無の 2 形を見る呼び出し元は 2 つ)、owner_override は
 * ワイルドカード展開のときの QNAME。
 * - RRset が入りきらない: RRset を丸ごと取り消して -1 (RFC 2181 §9: RRset の一部だけを返さない。呼び出し側で TC)。
 * - RRSIG が入りきらない: RRSIG だけ取り消す。rrsig_mode が RRSIG_REQUIRED (Answer / Authority) なら -1
 *   (RFC 4035 §3.1.1: TC を立てる)、RRSIG_OPTIONAL (Additional) なら RRset を残して成功扱い
 *   (§3.1.1: "MUST NOT set the TC bit solely because these RRSIG RRs didn't fit")。
 * 戻り値は書いたレコード数 (有効なレコードが無ければ 0)。 */
static int emit_rrset(zone_arena_t *zone, const size_t *idxs, int n_idx, const char *owner,
                      const char *owner_override, uint16_t type, uint16_t qclass, const rr_filter_t *f,
                      int rrsig_mode, uint8_t *res, size_t max_res_len, uint16_t *offset,
                      compress_ctx_t *comp_ctx, uint16_t *count, glue_list_t *glue) {
  uint16_t start_offset = *offset, start_count = *count;
  time_t now = zone->is_tinydns_format ? time(NULL) : 0;
  const dns_record_t *first = NULL;
  size_t first_idx = 0;
  int written = 0;
  for (int h = 0; h < n_idx; h++) {
    if (h > 0 && idxs[h] == idxs[0]) continue;
    for (int i = zone->hash_table[idxs[h]]; i != -1; i = zone->records[i].next_record) {
      dns_record_t *rec = &zone->records[i];
      if (rec->type_code != type || !domain_names_match_ci(rec->name, owner)) continue;
      uint16_t r_class = rec->class_val ? rec->class_val : 1;
      if (qclass != 255 && qclass != r_class) continue;
      if (f->answer_scope) note_ecs_variant(rec, type, f->zone_scope, f->answer_scope);
      uint32_t eff_ttl;
      if (!tinydns_record_currently_valid(rec, now, f->client_loc, f->client_ecs_tag, f->client_loc_tag, &eff_ttl))
        continue;
      dns_record_t rec_copy = *rec;
      rec_copy.ttl_value = eff_ttl;
      if (serialize_dns_record(res, max_res_len, offset, &rec_copy, comp_ctx, owner_override, 0xFFFFFFFF) < 0) {
        *offset = start_offset;
        *count = start_count;
        return -1;
      }
      (*count)++;
      written++;
      if (!first) {
        first = rec;
        first_idx = idxs[h];
      }
      if (glue) collect_additional_rr_glue(&rec_copy, glue->targets, &glue->count, glue->minimal);
    }
  }
  if (written == 0 || rrsig_mode == RRSIG_NONE || type == 46) return written;
  uint16_t rrset_offset = *offset, rrset_count = *count;
  if (!attach_covering_rrsig(zone, first_idx, first->name, owner_override, type, res, max_res_len, offset,
                             comp_ctx, count)) {
    *offset = rrset_offset;
    *count = rrset_count;
    if (rrsig_mode == RRSIG_REQUIRED) return -1;
  }
  return written;
}

/* ハッシュ表で name が入るバケット。名前の末尾のルートの '.' の有無で 2 形あるので両方返す (同じなら 1 つ)。 */
static int name_buckets(const zone_arena_t *zone, const char *name, size_t idxs[2]) {
  idxs[0] = calc_fnv1a_str(name) & (zone->hash_size - 1);
  if (name[0] == '\0') return 1;
  idxs[1] = calc_fnv1a_other_root_form(name) & (zone->hash_size - 1);
  return idxs[1] == idxs[0] ? 1 : 2;
}

static bool zone_has_rrset(const zone_arena_t *zone, const char *name, uint16_t type) {
  size_t idxs[2];
  int n = name_buckets(zone, name, idxs);
  for (int h = 0; h < n; h++)
    for (int i = zone->hash_table[idxs[h]]; i != -1; i = zone->records[i].next_record)
      if (zone->records[i].type_code == type && domain_names_match_ci(zone->records[i].name, name)) return true;
  return false;
}

/* R-03: name はこのゾーンの権威データか。頂点より下の名前 (name 自身を含む) に NS RRset があれば、そこはゾーン
 * カットで、name はグルー (権威データではなく署名されない。RFC 4035 §2.2、RFC 1034 §4.2.1)。 */
static bool name_is_authoritative(const zone_arena_t *zone, const char *name, const char *apex) {
  if (!domain_name_is_at_or_below(name, apex)) return false;
  for (const char *n = name; n && *n && !domain_names_match_ci(n, apex);) {
    if (zone_has_rrset(zone, n, 2)) return false;
    n = strchr_unescaped(n, '.');
    if (n) n++;
  }
  return true;
}

/* target の A と AAAA を zone から Additional セクションに書く (RRset ごとに、A の後に AAAA)。DO=1 で target が
 * このゾーンの権威データなら RRSIG も付ける (R-03、RFC 4035 §3.1.1。入りきらなければ RRSIG だけ落とし TC は
 * 立てない)。戻り値: 書いたレコード数、入りきらなければ -1。 */
static int append_additional_from_zone(zone_arena_t *zone, const char *apex, const char *target, bool dnssec_ok,
                                       const rr_filter_t *f, uint8_t *res, size_t max_res_len, uint16_t *offset,
                                       compress_ctx_t *comp_ctx, uint16_t *arcount) {
  if (zone->hash_size == 0 || !zone->hash_table) return 0;
  size_t idxs[2];
  int n = name_buckets(zone, target, idxs);
  int mode = (dnssec_ok && name_is_authoritative(zone, target, apex)) ? RRSIG_OPTIONAL : RRSIG_NONE;
  static const uint16_t types[2] = { 1, 28 };
  int total = 0;
  for (int t = 0; t < 2; t++) {
    int w = emit_rrset(zone, idxs, n, target, NULL, types[t], 255, f, mode, res, max_res_len, offset, comp_ctx,
                       arcount, NULL);
    if (w < 0) return -1;
    total += w;
  }
  return total;
}

STATIC_TEST bool append_glue_records(zone_arena_t *current_zone, const char *target,
                                     const char *zone_apex, uint8_t *res,
                                     size_t max_res_len, uint16_t *offset,
                                     compress_ctx_t *comp_ctx, uint16_t *arcount,
                                     const char client_loc[2],
                                     const char *client_ecs_tag,
                                     const char *client_loc_tag,
                                     additional_from_auth_t policy,
                                     view_snapshot_t *view, bool dnssec_ok) {

  if (!current_zone || !target || policy == ADDITIONAL_AUTH_NO) return true;

  // 1. Fast path: check prelinked glue. The copies carry no RRSIGs, so DO=1 takes the lookup below (R-03).
  if (!dnssec_ok && current_zone->prelinked_glue && current_zone->prelinked_glue_count > 0) {
    for (int e = 0; e < current_zone->prelinked_glue_count; e++) {
      prelinked_glue_entry_t *entry = &current_zone->prelinked_glue[e];
      if (entry->target_name && domain_names_match_ci(entry->target_name, target)) {
        time_t tinydns_now = current_zone->is_tinydns_format ? time(NULL) : 0;
        uint16_t start_offset = *offset, start_arcount = *arcount;
        for (int r = 0; r < entry->record_count; r++) {
          dns_record_t *rec = entry->records[r];
          if (!rec) continue;
          uint32_t eff_ttl;
          if (!tinydns_record_currently_valid(rec, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &eff_ttl)) continue;
          dns_record_t rec_copy = *rec;
          rec_copy.ttl_value = eff_ttl;
          if (serialize_dns_record(res, max_res_len, offset,
                                   &rec_copy, comp_ctx,
                                   NULL, 0xFFFFFFFF) < 0) {
            // RFC 2181 §9: この名前のアドレスは一部だけ残さない
            *offset = start_offset;
            *arcount = start_arcount;
            return false;
          } else {
            (*arcount)++;
          }
        }
        return true;
      }
    }
  }

  rr_filter_t f = { client_loc, client_ecs_tag, client_loc_tag, 0, NULL };

  // 2. In-zone search (covers in-domain glue and out-of-zone glue in current_zone)
  bool is_in_domain = domain_name_is_at_or_below(target, zone_apex);

  if (policy == ADDITIONAL_AUTH_IN_DOMAIN && !is_in_domain) {
    return true;
  }

  int w = append_additional_from_zone(current_zone, zone_apex, target, dnssec_ok, &f, res, max_res_len, offset,
                                      comp_ctx, arcount);
  if (w < 0) return false;
  if (w > 0) return true;

  // 3. Fallback: Search sibling authoritative zones in view dynamically if policy == ADDITIONAL_AUTH_YES
  if (policy == ADDITIONAL_AUTH_YES && view) {
    zone_db_entry_t *sib_entry = find_zone_in_view(view, target);
    if (sib_entry) {
      zone_arena_t *sib_arena = atomic_load_explicit(&sib_entry->rcu.active, memory_order_acquire);
      if (sib_arena && sib_arena != current_zone &&
          append_additional_from_zone(sib_arena, sib_entry->domain, target, dnssec_ok, &f, res, max_res_len,
                                      offset, comp_ctx, arcount) < 0)
        return false;
    }
  }

  return true;
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

/* NSEC index built by build_zone_index() (sorted in canonical order, RFC 4034 §6.1). No linear fallback (X-22): a
 * zone whose index could not be allocated is not loaded, so a zone without the index has no NSEC RRs. */
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
  return NULL;
}

STATIC_TEST bool name_exists_in_zone(zone_arena_t *zone, const char *name, const char client_loc[2], const char *client_ecs_tag, const char *client_loc_tag) {
  if (!zone || !name || !zone->hash_table || zone->hash_size == 0) return false;
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

  // 正規順序で name の次に来る名前が name の下にあれば、name は空の非終端 (ENT)
  const char *rn = zone->sorted_unique_names[pos];
  return domain_name_is_at_or_below(rn, name) && !domain_names_match_ci(rn, name);
}

STATIC_TEST const char *find_closest_encloser(zone_arena_t *zone, const char *qname, const char *zone_apex, const char client_loc[2], const char *client_ecs_tag, const char *client_loc_tag) {
  if (!zone || !qname || !zone_apex || !zone->hash_table || zone->hash_size == 0)
    return zone_apex;
  const char *parent = qname;
  while ((parent = strchr_unescaped(parent, '.')) != NULL) {
    parent++;
    if (*parent == '\0') break;

    if (domain_names_match_ci(parent, zone_apex))
      return zone_apex;
    if (!domain_name_is_at_or_below(parent, zone_apex))
      break; // Outside zone apex

    if (name_exists_in_zone(zone, parent, client_loc, client_ecs_tag, client_loc_tag)) {
      return parent;
    }
  }
  return zone_apex;
}


/* RFC 5155 §5 / RFC 4034 §6.2: NSEC3 ハッシュの入力は、完全修飾・非圧縮・英字小文字化した
 * ワイヤ形式のオーナー名。表示形式のエスケープ (\., \DDD) はオクテットに戻す。失敗なら 0。 */
STATIC_TEST size_t name_to_canonical_wire(const char *name, uint8_t *wire, size_t max_wire) {
    if (!name || max_wire < 1) return 0;
    long w = write_uncompressed_name_ext(wire, 0, max_wire, name, true);
    return w > 0 ? (size_t)w : 0;
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
    dns_base32hex_encode(digest, 20, out_b32, out_b32_sz);
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

/* RFC 5155 §7.2: every NSEC3 RR of an answer belongs to the chain whose parameters were used for hashing, i.e.
 * the NSEC3PARAM `param`. The chain is sorted in hash order (build_zone_index()), so both lookups are binary
 * searches (R-34); a zone without an index for these parameters has no usable NSEC3 RR. */

/* Index of the first entry whose hash is >= target (chain->count when there is none). */
static size_t nsec3_lower_bound(const nsec3_chain_t *chain, const char *target, size_t target_len) {
    size_t lo = 0, hi = chain->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const nsec3_index_entry_t *e = &chain->entries[mid];
        int c = strncasecmp(e->hash, target, e->hash_len < target_len ? e->hash_len : target_len);
        if (c == 0) c = e->hash_len < target_len ? -1 : (e->hash_len > target_len ? 1 : 0);
        if (c < 0) lo = mid + 1; else hi = mid;
    }
    return lo;
}

STATIC_TEST dns_record_t *find_matching_nsec3(zone_arena_t *zone, const dns_record_t *param,
                                              const char *hash_b32, const char *apex) {
    if (!zone || !param || !hash_b32 || !apex) return NULL;
    const nsec3_chain_t *chain = zone_find_nsec3_chain(zone, param);
    if (!chain) return NULL;
    size_t tlen = strlen(hash_b32);
    for (size_t i = nsec3_lower_bound(chain, hash_b32, tlen); i < chain->count; i++) {
        const nsec3_index_entry_t *e = &chain->entries[i];
        if (e->hash_len != tlen || strncasecmp(e->hash, hash_b32, tlen) != 0) break;
        /* RFC 5155 §3: the owner is the hashed label directly below the zone apex. */
        if (domain_names_match_ci(e->rec->name + e->hash_len + 1, apex)) return e->rec;
    }
    return NULL;
}

STATIC_TEST dns_record_t *find_covering_nsec3(zone_arena_t *zone, const dns_record_t *param,
                                              const char *target_hash) {
    if (!zone || !param || !target_hash) return NULL;
    const nsec3_chain_t *chain = zone_find_nsec3_chain(zone, param);
    if (!chain || chain->count == 0) return NULL;
    /* RFC 5155 §3.1.7: the covering RR is the last one in hash order whose owner hash is below the target; below
     * the first owner, the last RR of the chain covers the target (its next hash wraps to the first owner). */
    size_t i = nsec3_lower_bound(chain, target_hash, strlen(target_hash));
    const nsec3_index_entry_t *e = &chain->entries[i > 0 ? i - 1 : chain->count - 1];
    char owner_hash[64];
    memcpy(owner_hash, e->hash, e->hash_len);
    owner_hash[e->hash_len] = '\0';
    return nsec3_covers_hash(owner_hash, e->rec->rdata[4], target_hash) ? e->rec : NULL;
}

STATIC_TEST bool find_next_closer_name(const char *qname, const char *encloser, char *out, size_t out_sz) {
    if (!qname || !encloser || !out || out_sz == 0) return false;
    if (!domain_name_is_at_or_below(qname, encloser) || domain_names_match_ci(qname, encloser)) return false;
    /* RFC 5155 §1.3: next closer name = closest encloser に qname のラベルを 1 つ足した名前。
     * ラベル境界はエスケープされない '.' だけ。出力は末尾ドットなし。 */
    const char *start = qname;
    for (;;) {
        const char *dot = strchr_unescaped(start, '.');
        if (!dot) return false;
        if (domain_names_match_ci(dot + 1, encloser)) break;
        if (dot[1] == '\0') return false;
        start = dot + 1;
    }
    size_t nc_len = dns_name_len_no_root(start, strlen(start));
    if (nc_len + 1 >= out_sz) return false;
    memcpy(out, start, nc_len);
    out[nc_len] = '\0';
    return true;
}

/* O-17: 否定の証明に使う NSEC / NSEC3 を、その RRSIG と一緒に Authority に 1 回だけ書く (同じ RR が next closer の
 * cover とワイルドカードの証明を兼ねることがある。RFC 2181 §5: RRset に重複を入れない)。ttl は配信する TTL
 * (tinydns の有効期限による値。0xFFFFFFFF ならレコードの TTL)。false = 入りきらない: 呼び出し側は証明を
 * 取り消して TC を立てる (RFC 4035 §3.1.1、§3.1.3)。 */
static bool attach_denial_record(zone_arena_t *zone, dns_record_t *rec, uint32_t ttl,
                                 uint8_t *res, size_t max_res_len, uint16_t *offset,
                                 compress_ctx_t *comp_ctx, uint16_t *nscount,
                                 dns_record_t **attached, int *attached_count) {
    if (!rec) return true;
    for (int i = 0; i < *attached_count; i++) {
        if (attached[i] == rec) return true;
    }
    if (*attached_count < 8) attached[(*attached_count)++] = rec;

    dns_record_t rec_copy = *rec;
    if (ttl != 0xFFFFFFFF) rec_copy.ttl_value = ttl;
    if (serialize_dns_record(res, max_res_len, offset, &rec_copy, comp_ctx, NULL, 0xFFFFFFFF) < 0) {
        return false;
    }
    (*nscount)++;
    uint32_t c_hash = calc_fnv1a_str(rec->name);
    size_t c_idx = c_hash & (zone->hash_size - 1);
    return attach_covering_rrsig(zone, c_idx, rec->name, NULL, rec->type_code,
                                 res, max_res_len, offset, comp_ctx, nscount);
}

STATIC_TEST bool attach_nsec3_record(zone_arena_t *zone, dns_record_t *rec,
                                uint8_t *res, size_t max_res_len, uint16_t *offset,
                                compress_ctx_t *comp_ctx, uint16_t *nscount,
                                dns_record_t **attached, int *attached_count) {
    return attach_denial_record(zone, rec, 0xFFFFFFFF, res, max_res_len, offset, comp_ctx, nscount,
                                attached, attached_count);
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
    rr_filter_t flt = { client_loc, client_ecs_tag, client_loc_tag, 0, NULL };
    // 委任の NS は子ゾーンのデータで署名されない (RFC 4035 §2.2)。入りきらなければ NS を丸ごと外して TC。
    int ns_written = emit_rrset(current_zone, &idx, 1, name, NULL, 2, 255, &flt, RRSIG_NONE, res, max_res_len,
                                offset, comp_ctx, nscount, NULL);
    if (ns_written < 0) {
      res[2] &= ~0x04;
      res[2] |= 0x02;
      return true;
    }
    if (ns_written > 0) {
      res[2] &= ~0x04; // Clear AA (Referral response MUST NOT have AA set)

      // DNSSEC delegation handling (RFC 4035 §3.1.4 / RFC 5155 §7.2.3)
      if (dnssec_ok) {
        int ds_written = emit_rrset(current_zone, &idx, 1, name, NULL, 43, 255, &flt, RRSIG_REQUIRED, res,
                                    max_res_len, offset, comp_ctx, nscount, NULL);
        if (ds_written < 0) {
          res[2] |= 0x02;
          return true;
        }
        if (ds_written == 0) {
          // Insecure Delegation: Prove non-existence of DS (RFC 4035 §3.1.4 / RFC 5155 §7.2.3)
          dns_record_t *attached[8];
          int attached_cnt = 0;
          const nsec3_params_t *n3 = zone_nsec3(current_zone, zone_apex);
          if (!n3) {
            dns_record_t *nsec = NULL;
            uint32_t nsec_ttl = 0xFFFFFFFF;
            for (int i = current_zone->hash_table[idx]; i != -1;
                 i = current_zone->records[i].next_record) {
              dns_record_t *rec = &current_zone->records[i];
              if (rec->type_code == 47 /* NSEC */ && strcasecmp(rec->name, name) == 0) {
                if (rec->rdata_count < 1) break;
                if (!tinydns_record_currently_valid(rec, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &nsec_ttl)) continue;
                nsec = rec;
                break;
              }
            }
            if (!nsec) {
              nsec = find_covering_nsec(current_zone, name);
              nsec_ttl = 0xFFFFFFFF;
            }
            if (!attach_denial_record(current_zone, nsec, nsec_ttl, res, max_res_len, offset, comp_ctx, nscount,
                                      attached, &attached_cnt)) {
              res[2] |= 0x02;
              return true;
            }
          } else {
            // NSEC3 Insecure Delegation Proof (RFC 5155 §7.2.3)
            {
              const dns_record_t *param_rec = n3->param;
              uint8_t algo = n3->algorithm;
              uint16_t iterations = n3->iterations;
              const uint8_t *salt = n3->salt;
              size_t salt_len = n3->salt_len;

              char q_hash[64];
              if (compute_nsec3_hash(name, algo, iterations, salt, salt_len, q_hash, sizeof(q_hash))) {
                dns_record_t *m_rec = find_matching_nsec3(current_zone, param_rec, q_hash, zone_apex);
                if (m_rec) {
                  if (!attach_nsec3_record(current_zone, m_rec, res, max_res_len, offset, comp_ctx, nscount, attached, &attached_cnt)) {
                    res[2] |= 0x02;
                    return true;
                  }
                } else {
                  // Opt-Out: Next Closer covering NSEC3 and Closest Provable Encloser matching NSEC3 (RFC 5155 §7.2.3)
                  dns_record_t *c_rec = find_covering_nsec3(current_zone, param_rec, q_hash);
                  if (c_rec) {
                    if (!attach_nsec3_record(current_zone, c_rec, res, max_res_len, offset, comp_ctx, nscount, attached, &attached_cnt)) {
                      res[2] |= 0x02;
                      return true;
                    }
                  }
                  const char *encloser = find_closest_encloser(current_zone, name, zone_apex, client_loc, client_ecs_tag, client_loc_tag);
                  if (encloser) {
                    char ce_hash[64];
                    if (compute_nsec3_hash(encloser, algo, iterations, salt, salt_len, ce_hash, sizeof(ce_hash))) {
                      dns_record_t *ce_rec = find_matching_nsec3(current_zone, param_rec, ce_hash, zone_apex);
                      if (ce_rec) {
                        if (!attach_nsec3_record(current_zone, ce_rec, res, max_res_len, offset, comp_ctx, nscount, attached, &attached_cnt)) {
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
                                   max_res_len, offset, comp_ctx, arcount, client_loc, client_ecs_tag, client_loc_tag, policy, view,
                                   dnssec_ok)) {
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

/* RFC 7871 §7.2.1: Answer セクションに入れる RRset にサブネット別の変種 (ECS タグ付きレコード) が
 * あれば、クライアントに一致したかどうかに関係なく、応答はサブネットに依存する。そのゾーンで求めた
 * SCOPE を応答の SCOPE にする (複数の RRset や CNAME 先のゾーンがあれば最長のもの)。 */
static inline void note_ecs_variant(const dns_record_t *rec, uint16_t qtype, uint8_t zone_scope,
                                    uint8_t *answer_scope) {
  if (rec->ecs_subnet_tag == NULL) return;
  if (qtype != 255 && rec->type_code != qtype && rec->type_code != 5 && rec->type_code != 39) return;
  if (zone_scope > *answer_scope) *answer_scope = zone_scope;
}

/* types[] にまだ無ければ t を加えて false、既にあれば true (同じ名前の RRset を 1 回だけ書くため) */
static bool rrset_type_seen(uint16_t types[64], int *count, uint16_t t) {
  for (int i = 0; i < *count; i++)
    if (types[i] == t) return true;
  if (*count < 64) types[(*count)++] = t;
  return false;
}

static void resolve_name_answer(const char *qname, uint16_t qclass, const uint16_t *qtypes, int num_qtypes,
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
                         uint8_t *answer_scope) {
  if (qtx_included_out) *qtx_included_out = 0;
  uint16_t initial_offset = *offset;
  uint16_t initial_ancount = *ancount;
  uint16_t initial_nscount = *nscount;
  uint16_t initial_arcount = *arcount;
  char current_qname[DNS_NAME_TEXT_SIZE];
  strlcpy(current_qname, qname, sizeof(current_qname));
  size_t current_qname_len = strlen(current_qname);
  uint32_t current_qname_hash = calc_fnv1a_str(current_qname);
  char visited_qnames[16][DNS_NAME_TEXT_SIZE];
  int visited_count = 0;
  strlcpy(visited_qnames[visited_count++], current_qname, sizeof(visited_qnames[0]));
  glue_list_t glue;
  memset(&glue, 0, sizeof(glue));
  glue.minimal = minimal_responses;
  /* R-04: RRSIG 自体が要求されたとき (QTYPE RRSIG、または MQTYPE に RRSIG) は、その名前の RRSIG が全部その
   * RRset に入るので、他の RRset には付けない (同じ RRSIG を 2 回書かない。RFC 2181 §5)。 */
  bool rrsig_requested = false;
  for (int k = 0; k < num_qtypes; k++)
    if (qtypes[k] == 46) rrsig_requested = true;
  bool sign_answers = dnssec_ok && !rrsig_requested;
  bool chain_exhausted = true;
  bool any_cname_wc_expanded = false;
  char first_wc_qname[DNS_NAME_TEXT_SIZE] = {0};
  zone_arena_t *first_wc_zone = NULL;
  char first_wc_apex[DNS_NAME_TEXT_SIZE] = {0};
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
    uint8_t zone_scope = 0;
    if (ecs_trusted && ecs_addr) {
      client_ecs_tag = resolve_ecs_subnet_tag(current_zone, cfg, zcfg, ecs_addr, ecs_family, &zone_scope);
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
    uint16_t written_types[64];
    int written_count = 0;
    rr_filter_t flt = { client_loc, client_ecs_tag, client_loc_tag, zone_scope, answer_scope };
    bool has_any = (qtypes[0] == 255);
    bool skip_synthesis = false;
    if (has_any && minimal_any) {
      bool name_exists = false, has_cname = false, has_rrsig = false;
      for (int i = current_zone->hash_table[idx]; i != -1;
           i = current_zone->records[i].next_record) {
        dns_record_t *rec = &current_zone->records[i];
        if (strcasecmp(rec->name, current_qname) == 0) {
          uint32_t eff_ttl;
          note_ecs_variant(rec, 255, zone_scope, answer_scope);
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
        note_ecs_variant(rec, qtypes[0], zone_scope, answer_scope);
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
          if (serialize_dns_record(res, max_res_len, offset, &rec_copy, comp_ctx,
                                   NULL, 0xFFFFFFFF) < 0) {
            res[2] |= 0x02;
            return;
          } else
            (*ancount)++;
          if (dnssec_ok) {
            if (!attach_covering_rrsig(current_zone, idx, current_qname, NULL, 5,
                                      res, max_res_len, offset, comp_ctx, ancount)) {
              res[2] |= 0x02;
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
            // R-04: DO=1 の ANY では RRSIG は各 RRset の後ろに付けるだけで、単独のレコードとしては書かない
            if (has_any && dnssec_ok && rec_type == 46) continue;
            type_matched = true;
            // O-16: RRset はタイプごとに 1 回、全レコードを続けて書き、その後ろに RRSIG
            if (rrset_type_seen(written_types, &written_count, rec_type)) continue;
            if (emit_rrset(current_zone, &idx, 1, current_qname, NULL, rec_type, qclass, &flt,
                           (sign_answers && rec_type != 46) ? RRSIG_REQUIRED : RRSIG_NONE, res, max_res_len, offset,
                           comp_ctx, ancount, &glue) < 0) {
              res[2] |= 0x02;
              return;
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
            note_ecs_variant(rec, 39, zone_scope, answer_scope);
            if (!tinydns_record_currently_valid(rec, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &eff_ttl)) continue;
            dname_found = true;
            if (rec->rdata_count == 0) break;

            // 先に DNAME レコード自身を Answer セクションに追加
            dns_record_t rec_copy = *rec;
            rec_copy.ttl_value = eff_ttl;
            if (serialize_dns_record(res, max_res_len, offset, &rec_copy, comp_ctx, NULL, 0xFFFFFFFF) < 0) {
              res[2] |= 0x02;
              return;
            }
            (*ancount)++;
            if (dnssec_ok) {
              if (!attach_covering_rrsig(current_zone, p_idx, dname_parent, NULL, 39, res, max_res_len, offset, comp_ctx, ancount)) {
                res[2] |= 0x02;
                return;
              }
            }

            // [RFC 6672 §4.1] 合成名が 255 オクテットを超えるなら、合成 CNAME は含めず、
            // DNAME のみを載せて YXDOMAIN を返す。長さはワイヤ形式で数える (テキストの長さは
            // エスケープの分だけ長い)。
            size_t prefix_len = dname_parent - current_qname;
            char synth_name[DNS_NAME_TEXT_SIZE];
            uint8_t synth_wire[256];
            memcpy(synth_name, current_qname, prefix_len);
            int written = snprintf(synth_name + prefix_len, sizeof(synth_name) - prefix_len, "%s", rec->rdata[0]);
            if (written < 0 || (size_t)written >= sizeof(synth_name) - prefix_len ||
                write_uncompressed_name_ext(synth_wire, 0, sizeof(synth_wire), synth_name, false) < 0) {
              res[3] = (res[3] & 0xF0) | 6; // YXDOMAIN
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
        char wc_name[DNS_NAME_TEXT_SIZE];
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
            uint16_t wc_written_types[64];
            int wc_written_count = 0;
            for (int i = current_zone->hash_table[wc_idx]; i != -1;
                 i = current_zone->records[i].next_record) {
              dns_record_t *rec = &current_zone->records[i];
              if (strcasecmp(rec->name, wc_name) == 0) {
                uint16_t r_class = rec->class_val ? rec->class_val : 1;
                bool class_matches = (qclass == 255 || qclass == r_class);
                if (!class_matches) continue;
                uint32_t eff_ttl;
                note_ecs_variant(rec, qtypes[0], zone_scope, answer_scope);
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
                  if (serialize_dns_record(res, max_res_len, offset, &rec_copy, comp_ctx,
                                           current_qname, 0xFFFFFFFF) < 0) {
                    res[2] |= 0x02;
                    return;
                  } else
                    (*ancount)++;
                  if (dnssec_ok) {
                    if (!attach_covering_rrsig(current_zone, wc_idx, wc_name, current_qname, 5,
                                              res, max_res_len, offset, comp_ctx, ancount)) {
                      res[2] |= 0x02;
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
                    // R-04 / O-16: exact-name の場合と同じ (RRSIG は各 RRset の後ろ、RRset ごとに 1 回)
                    if (has_any && dnssec_ok && rec_type == 46) continue;
                    type_matched = true;
                    if (rrset_type_seen(wc_written_types, &wc_written_count, rec_type)) continue;
                    if (emit_rrset(current_zone, &wc_idx, 1, wc_name, current_qname, rec_type, qclass, &flt,
                                   (sign_answers && rec_type != 46) ? RRSIG_REQUIRED : RRSIG_NONE, res, max_res_len,
                                   offset, comp_ctx, ancount, &glue) < 0) {
                      res[2] |= 0x02;
                      return;
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
      /* R-32: 対象がこのゾーンの頂点で QTYPE が DS なら、同じゾーンで続けずに親ゾーンを探す */
      bool in_zone = domain_name_is_at_or_below(current_qname, db_entry->domain) &&
                     !(qtypes[0] == 43 && domain_names_match_ci(current_qname, db_entry->domain));
      if (in_zone)
        continue;
      else {
        zone_db_entry_t *new_db_entry = find_zone_for_query(view, current_qname, qtypes[0]); // R-32
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
        int saved_glue_count = glue.count;
        resolve_checkpoint_t cp = save_checkpoint(offset, ancount, nscount, arcount);
        int qtx_mode = (sign_answers && qtx != 46) ? RRSIG_REQUIRED : RRSIG_NONE;

        // O-16: RRset を続けて書き、その後ろに RRSIG (exact-name と同じヘルパー)
        int w = emit_rrset(current_zone, &final_idx, 1, current_qname, NULL, qtx, qclass, &flt, qtx_mode, res,
                           max_res_len, offset, comp_ctx, ancount, &glue);
        if (w < 0) this_qtx_failed = true;
        else if (w > 0) qtx_matched = true;

        if (!qtx_matched && !this_qtx_failed) {
          const char *parent = current_qname;
          char wc_name[DNS_NAME_TEXT_SIZE];
          wc_name[0] = '*'; wc_name[1] = '.';
          while ((parent = strchr_unescaped(parent, '.')) != NULL) {
            parent++; if (*parent == '\0') break;
            size_t parent_len = current_qname_len - (size_t)(parent - current_qname);
            if (parent_len + 3 > sizeof(wc_name)) break;
            uint32_t wc_hash = calc_fnv1a_continue(FNV1A_WILDCARD_PREFIX_HASH, parent);
            size_t wc_idx = wc_hash & (current_zone->hash_size - 1);
            wc_found = false;
            if (current_zone->hash_table[wc_idx] != -1) {
              memcpy(&wc_name[2], parent, parent_len + 1);
              int ww = emit_rrset(current_zone, &wc_idx, 1, wc_name, current_qname, qtx, qclass, &flt, qtx_mode,
                                  res, max_res_len, offset, comp_ctx, ancount, &glue);
              if (ww < 0) this_qtx_failed = true;
              else if (ww > 0) wc_found = qtx_matched = true;
            }
            if (wc_found || this_qtx_failed) break;

            // ★重要: RFC 4592 準拠 (親存在チェック)
            if (name_exists_in_zone(current_zone, parent, client_loc, client_ecs_tag, client_loc_tag))
              break;
          }
        }

        if (this_qtx_failed) {
          restore_checkpoint(&cp, offset, ancount, nscount, arcount);
          glue.count = saved_glue_count;
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
        if (dlen > 0 && dns_name_len_no_root(apex_lookup, dlen) == dlen && dlen + 2 <= sizeof(dot_buf)) {
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
    const nsec3_params_t *n3 = dnssec_ok ? zone_nsec3(current_zone, db_entry->domain) : NULL;
    if (dnssec_ok && !n3) {
      /* O-17: attach_denial_record() は同じ NSEC を 2 回書かず、RRSIG が入らないときも失敗を返す */
      if (found && wc_found) {
        // RFC 4035 §3.1.3.3: Wildcard answer proof (QNAME non-existence)
        dns_record_t *cover = find_covering_nsec(current_zone, current_qname);
        if (!attach_denial_record(current_zone, cover, 0xFFFFFFFF, res, max_res_len, offset, comp_ctx, nscount,
                                  nsec_attached, &nsec_attached_cnt))
          nsec_failed = true;
        if (!all_matched && !nsec_failed) {
          // RFC 4035 §3.1.3.4: wildcard NODATA: the NSEC of the wildcard owner proves the type is missing
          const char *encloser = find_closest_encloser(current_zone, current_qname, db_entry->domain, client_loc, client_ecs_tag, client_loc_tag);
          if (encloser) {
            char wc_name[DNS_NAME_TEXT_SIZE];
            snprintf(wc_name, sizeof(wc_name), "*.%s", encloser);
            uint32_t wc_hash = calc_fnv1a_str(wc_name);
            size_t wc_idx = wc_hash & (current_zone->hash_size - 1);
            for (int i = current_zone->hash_table[wc_idx]; i != -1; i = current_zone->records[i].next_record) {
              dns_record_t *rec = &current_zone->records[i];
              if (rec->type_code == 47 && strcasecmp(rec->name, wc_name) == 0) {
                if (!attach_denial_record(current_zone, rec, 0xFFFFFFFF, res, max_res_len, offset, comp_ctx,
                                          nscount, nsec_attached, &nsec_attached_cnt))
                  nsec_failed = true;
                break;
              }
            }
          }
        }
      } else if (found && !all_matched) {
        bool nsec_at_name = false;
        for (int i = current_zone->hash_table[idx]; i != -1;
             i = current_zone->records[i].next_record) {
          dns_record_t *rec = &current_zone->records[i];
          if (rec->type_code == 47 /* NSEC */ &&
              strcasecmp(rec->name, current_qname) == 0) {
            if (rec->rdata_count < 1) break; // 壊れたNSECは無視
            uint32_t eff_ttl;
            if (!tinydns_record_currently_valid(rec, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &eff_ttl)) continue;
            nsec_at_name = true;
            if (!attach_denial_record(current_zone, rec, eff_ttl, res, max_res_len, offset, comp_ctx, nscount,
                                      nsec_attached, &nsec_attached_cnt))
              nsec_failed = true;
            break;
          }
        }
        if (ent_nodata && !nsec_failed && !nsec_at_name) {
          // An ENT owns no NSEC; the NSEC that covers it (its next name is a descendant) proves it exists.
          dns_record_t *cover = find_covering_nsec(current_zone, current_qname);
          if (!attach_denial_record(current_zone, cover, 0xFFFFFFFF, res, max_res_len, offset, comp_ctx, nscount,
                                    nsec_attached, &nsec_attached_cnt))
            nsec_failed = true;
        }
      } else if (!found) {
        dns_record_t *cover = find_covering_nsec(current_zone, current_qname);
        if (!attach_denial_record(current_zone, cover, 0xFFFFFFFF, res, max_res_len, offset, comp_ctx, nscount,
                                  nsec_attached, &nsec_attached_cnt))
          nsec_failed = true;

        if (!nsec_failed) {
          const char *encloser = find_closest_encloser(current_zone, current_qname, db_entry->domain, client_loc, client_ecs_tag, client_loc_tag);
          if (encloser) {
            char wc_name[DNS_NAME_TEXT_SIZE];
            int written = snprintf(wc_name, sizeof(wc_name), "*.%s", encloser);
            if (written > 0 && (size_t)written < sizeof(wc_name)) {
              if (!cover || !nsec_covers_name(cover, wc_name)) {
                dns_record_t *wc_cover = find_covering_nsec(current_zone, wc_name);
                if (!attach_denial_record(current_zone, wc_cover, 0xFFFFFFFF, res, max_res_len, offset, comp_ctx,
                                          nscount, nsec_attached, &nsec_attached_cnt))
                  nsec_failed = true;
              }
            }
          }
        }
      }
    } else if (n3) {
      {
        const dns_record_t *param_rec = n3->param;
        uint8_t algo = n3->algorithm;
        uint16_t iterations = n3->iterations;
        const uint8_t *salt = n3->salt;
        size_t salt_len = n3->salt_len;

        if (found && wc_found) {
          // RFC 5155 §7.2.5 & §8.5: Wildcard answer proof (Closest Encloser & Next Closer covering)
          const char *encloser = find_closest_encloser(current_zone, current_qname, db_entry->domain, client_loc, client_ecs_tag, client_loc_tag);
          if (!encloser) encloser = db_entry->domain;
          char ce_hash[64];
          if (compute_nsec3_hash(encloser, algo, iterations, salt, salt_len, ce_hash, sizeof(ce_hash))) {
            dns_record_t *ce_rec = find_matching_nsec3(current_zone, param_rec, ce_hash, db_entry->domain);
            if (ce_rec) {
              if (!attach_nsec3_record(current_zone, ce_rec, res, max_res_len, offset, comp_ctx, nscount, attached_nsec3, &attached_nsec3_cnt)) {
                nsec_failed = true;
              }
            }
          }

          char nc_name[DNS_NAME_TEXT_SIZE];
          if (!nsec_failed && find_next_closer_name(current_qname, encloser, nc_name, sizeof(nc_name))) {
            char nc_hash[64];
            if (compute_nsec3_hash(nc_name, algo, iterations, salt, salt_len, nc_hash, sizeof(nc_hash))) {
              dns_record_t *nc_cover = find_covering_nsec3(current_zone, param_rec, nc_hash);
              if (nc_cover) {
                if (!attach_nsec3_record(current_zone, nc_cover, res, max_res_len, offset, comp_ctx, nscount, attached_nsec3, &attached_nsec3_cnt)) {
                  nsec_failed = true;
                }
              }
            }
          }

          if (!all_matched && !nsec_failed) {
            char wc_name[DNS_NAME_TEXT_SIZE];
            snprintf(wc_name, sizeof(wc_name), "*.%s", encloser);
            char wc_hash[64];
            if (compute_nsec3_hash(wc_name, algo, iterations, salt, salt_len, wc_hash, sizeof(wc_hash))) {
              dns_record_t *wc_rec = find_matching_nsec3(current_zone, param_rec, wc_hash, db_entry->domain);
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
            dns_record_t *m_rec = find_matching_nsec3(current_zone, param_rec, q_hash, db_entry->domain);
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
            dns_record_t *ce_rec = find_matching_nsec3(current_zone, param_rec, ce_hash, db_entry->domain);
            if (ce_rec) {
              if (!attach_nsec3_record(current_zone, ce_rec, res, max_res_len, offset, comp_ctx, nscount, attached_nsec3, &attached_nsec3_cnt)) {
                nsec_failed = true;
              }
            }
          }

          char nc_name[DNS_NAME_TEXT_SIZE];
          if (!nsec_failed && find_next_closer_name(current_qname, encloser, nc_name, sizeof(nc_name))) {
            char nc_hash[64];
            if (compute_nsec3_hash(nc_name, algo, iterations, salt, salt_len, nc_hash, sizeof(nc_hash))) {
              dns_record_t *nc_cover = find_covering_nsec3(current_zone, param_rec, nc_hash);
              if (nc_cover) {
                if (!attach_nsec3_record(current_zone, nc_cover, res, max_res_len, offset, comp_ctx, nscount, attached_nsec3, &attached_nsec3_cnt)) {
                  nsec_failed = true;
                }
              }
            }
          }

          char wc_name[DNS_NAME_TEXT_SIZE];
          snprintf(wc_name, sizeof(wc_name), "*.%s", encloser);
          char wc_hash[64];
          if (!nsec_failed && compute_nsec3_hash(wc_name, algo, iterations, salt, salt_len, wc_hash, sizeof(wc_hash))) {
            dns_record_t *wc_cover = find_covering_nsec3(current_zone, param_rec, wc_hash);
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
      const nsec3_params_t *wc_n3 = zone_nsec3(wc_zone, wc_apex);
      if (!wc_n3) {
        dns_record_t *cover = find_covering_nsec(wc_zone, first_wc_qname);
        if (!attach_denial_record(wc_zone, cover, 0xFFFFFFFF, res, max_res_len, offset, comp_ctx, nscount,
                                  nsec_attached, &nsec_attached_cnt))
          nsec_failed = true;
      } else {
        {
          const dns_record_t *p_rec = wc_n3->param;
          uint8_t algo = wc_n3->algorithm;
          uint16_t iterations = wc_n3->iterations;
          const uint8_t *salt = wc_n3->salt;
          size_t salt_len = wc_n3->salt_len;

          const char *encloser = find_closest_encloser(wc_zone, first_wc_qname, wc_apex, client_loc, client_ecs_tag, client_loc_tag);
          if (!encloser) encloser = wc_apex;
          char ce_hash[64];
          if (compute_nsec3_hash(encloser, algo, iterations, salt, salt_len, ce_hash, sizeof(ce_hash))) {
            dns_record_t *ce_rec = find_matching_nsec3(wc_zone, p_rec, ce_hash, wc_apex);
            if (ce_rec) {
              if (!attach_nsec3_record(wc_zone, ce_rec, res, max_res_len, offset, comp_ctx, nscount, attached_nsec3, &attached_nsec3_cnt)) {
                nsec_failed = true;
              }
            }
          }

          char nc_name[DNS_NAME_TEXT_SIZE];
          if (!nsec_failed && find_next_closer_name(first_wc_qname, encloser, nc_name, sizeof(nc_name))) {
            char nc_hash[64];
            if (compute_nsec3_hash(nc_name, algo, iterations, salt, salt_len, nc_hash, sizeof(nc_hash))) {
              dns_record_t *nc_cover = find_covering_nsec3(wc_zone, p_rec, nc_hash);
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
      /* 決定事項 2: 否定の証明 (NSEC/NSEC3 と RRSIG) は Authority の署名付き RRset で、省けば署名の無い応答に
       * 見える。入りきらなければ証明を外して TC を立てる (RFC 4035 §3.1.1、§3.1.3)。 */
      restore_checkpoint(&nsec_cp, offset, ancount, nscount, arcount);
      res[2] |= 0x02;
      return;
    }
    
    // ==== フェーズ9: Authority NS/Glue付加 ====
    bool needs_ns = false;
    if (qtypes[0] != 2 && qtypes[0] != 255) { needs_ns = true; }
    if (type_matched && !minimal_responses && needs_ns) {
      /* R-03: 頂点の NS は署名された RRset。DO=1 なら RRSIG(NS) も付け、入りきらなければ TC (RFC 4035 §3.1.1) */
      size_t apex_idxs[2];
      int n_apex = name_buckets(current_zone, db_entry->domain, apex_idxs);
      rr_filter_t ns_flt = { client_loc, client_ecs_tag, client_loc_tag, 0, NULL };
      if (emit_rrset(current_zone, apex_idxs, n_apex, db_entry->domain, NULL, 2, 255, &ns_flt,
                     dnssec_ok ? RRSIG_REQUIRED : RRSIG_NONE, res, max_res_len, offset, comp_ctx, nscount,
                     &glue) < 0) {
        res[2] |= 0x02;
        return;
      }
    }

    // ==== フェーズ10: Additional Glue付加 ====
    if (!minimal_responses && glue.count > 0 && policy != ADDITIONAL_AUTH_NO) {
      for (int k = 0; k < glue.count; k++) {
        if (!append_glue_records(current_zone, glue.targets[k], db_entry->domain,
                                 res, max_res_len, offset, comp_ctx, arcount,
                                 client_loc, client_ecs_tag, client_loc_tag, policy, view, dnssec_ok)) {
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
  }
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
  /* SCOPE は SOURCE PREFIX-LENGTH で切り詰めない。長い SCOPE は「SOURCE では足りない」の
   * 意味になる (RFC 7871 §7.2.1)。 */
  (void)ecs_source_prefix;
  uint16_t initial_ancount = *ancount;
  uint8_t answer_scope = 0;
  resolve_name_answer(qname, qclass, qtypes, num_qtypes, db_entry_ptr, current_zone_ptr, res,
                      max_res_len, offset, comp_ctx, ancount, nscount, arcount, minimal_responses,
                      minimal_any, minimal_any_ttl, dnssec_ok, view, qtx_included_out, client_ip, cfg,
                      ecs_trusted, ecs_addr, ecs_family, &answer_scope);
  /* RFC 7871 §7.4: 否定応答 (NXDOMAIN/NODATA) と委任は SCOPE 0 (SHOULD)。SERVFAIL なども 0。 */
  bool positive = (res[3] & 0x0F) == 0 && *ancount > initial_ancount;
  if (out_ecs_scope_prefix) *out_ecs_scope_prefix = positive ? answer_scope : 0;
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

program_plugin_t *find_program_plugin(const char *view_name, const char *domain) {
  if (!view_name || !domain) return NULL;
  for (int i = 0; i < g_program_plugins_count; i++) {
    if (strcasecmp(g_program_plugins[i].view_name, view_name) == 0 &&
        strcasecmp(g_program_plugins[i].domain, domain) == 0)
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
  /* [M-4] 質問セクションが入らないときは QDCOUNT=0 でヘッダだけにする
   * (途中までの質問を返すと QDCOUNT と内容が食い違う)。*/
  size_t copy_len = q_end > max_res_len ? DNS_HEADER_SIZE : q_end;
  memcpy(res, req, copy_len);
  dns_init_response_header(res, req, 2, false); // SERVFAIL、AA/TC/RA/Z/AD=0 (R-05)
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

/* max_res_len: 応答の上限 (UDP ではクライアントの上限。超えたら TC=1 に切り詰める)。
 * res_cap: res の容量。disable-auto-tc-flag yes のときは max_res_len を超えてもそのまま返すが、
 * res_cap は超えない (O-01)。res_cap を超える応答は TC=1 に切り詰める。 */
STATIC_TEST int dispatch_to_program_zone(const char *view_name, const char *domain,
                                    const uint8_t *req, size_t req_len,
                                    uint8_t *res, size_t max_res_len, size_t res_cap,
                                    const char *client_ip, bool is_tcp) {
  if (max_res_len > res_cap) max_res_len = res_cap;
  program_plugin_t *plugin = find_program_plugin(view_name, domain);
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
      } else if (plugin->disable_auto_tc_flag && resp_len <= res_cap) {
        // disable-auto-tc-flag yes (default: no): do not truncate or force TC=1; send full response as-is
        // (up to 65535, but never more than the response buffer holds: O-01)
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
               domain, (unsigned int)resp_len, plugin->disable_auto_tc_flag ? res_cap : max_res_len);
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

bool spawn_one_program_plugin(zone_config_t *zcfg, const char *view_name, program_plugin_t *out) {
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
      if (geteuid() == 0) {
        if (setgroups(0, NULL) != 0) _exit(126);
        if (setgid(pwd->pw_gid) != 0) _exit(126);
        if (setuid(pwd->pw_uid) != 0) _exit(126);
      } else if (pwd->pw_uid != geteuid() || pwd->pw_uid != getuid()) {
        // 非root起動では別ユーザーへ切り替えられない。main()の起動前検証
        // (validate_program_zone_users) で弾かれるはずだが念のため fail-closed。
        fprintf(stderr, "[FATAL] Zone '%s': program-user '%s' differs from the non-root user "
                "karidns runs as; refusing to exec plugin.\n", zcfg->domain, zcfg->program_user);
        _exit(126);
      }
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
  strlcpy(out->view_name, view_name ? view_name : "", sizeof(out->view_name));
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
      if (spawn_one_program_plugin(z, v->name, &g_program_plugins[idx])) idx++;
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

void build_zone_response_cache(zone_arena_t *arena, server_config_t *cfg, const char *view_name, const char *domain) {
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

  // O-07: 同じゾーン名が別の view にもあるので、このエントリの view の設定を見る
  zone_config_t *zcfg = cfg ? find_zone_config_in_view(cfg, view_name, domain) : NULL;
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


/* program / forward ゾーンの応答のうち、質問セクションだけのもの (上限超過で切り詰めた TC=1 応答、
 * KariDNS が合成した SERVFAIL、上流が OPT なしで返したエラー) には OPT が無い。問い合わせに OPT が
 * あれば付ける (RFC 6891 §6.1.1、§7)。AR=0 なので TSIG の後ろに付けてしまうことはない。 */
static int add_opt_to_bare_passthrough(uint8_t *res, size_t max_res_len, int len,
                                       edns_info_t *edns, bool is_tcp, server_config_t *cfg) {
  if (len < DNS_HEADER_SIZE || !edns->present) return len;
  if ((res[6] | res[7] | res[8] | res[9] | res[10] | res[11]) != 0) return len;
  uint16_t offset = (uint16_t)len;
  uint16_t arcount = (uint16_t)((res[10] << 8) | res[11]);
  assemble_edns_opt(res, max_res_len, &offset, &arcount, edns, 0, is_tcp, cfg);
  res[10] = (uint8_t)(arcount >> 8);
  res[11] = (uint8_t)(arcount & 0xFF);
  return (int)offset;
}

int process_dns_query_impl(const uint8_t *req, size_t req_len, uint8_t *res,
                            size_t max_res_len, const char *qname, uint16_t qtype,
                            const char *client_ip, compress_ctx_t *comp_ctx,
                            bool is_tcp, rate_limit_config_t **out_rrl_cfg,
                            zone_db_snapshot_t *snap, server_config_t *cfg,
                            zone_db_entry_t **out_matched_entry) {
  return process_dns_query_impl_cap(req, req_len, res, max_res_len, 0, qname, qtype, client_ip, comp_ctx,
                                    is_tcp, out_rrl_cfg, snap, cfg, out_matched_entry);
}

static int process_query_body(const uint8_t *req, size_t req_len, uint8_t *res,
                              size_t max_res_len, size_t res_cap, const char *qname, uint16_t qtype,
                              const char *client_ip, compress_ctx_t *comp_ctx,
                              bool is_tcp, rate_limit_config_t **out_rrl_cfg,
                              zone_db_snapshot_t *snap, server_config_t *cfg,
                              zone_db_entry_t **out_matched_entry, tsig_request_t *tsig);

/* res_cap: res の実際の容量 (バイト)。0 なら不明で、従来どおり max_res_len (UDP では EDNS の
 * サイズに置き換えた後の値) を容量とみなす。max_res_len は応答の上限 (UDP ではクライアントの上限)。 */
/* RFC 8945 §5.2、§5.3: TSIG の付いた要求は、どの OPCODE でも先に TSIG を検証し (鍵は要求の鍵名と
 * アルゴリズムで決める)、TSIG RR を除いた要求を処理して、応答に TSIG を付ける (検証できれば同じ鍵で
 * 署名、鍵と MAC のエラーは無署名)。TSIG のエラーは NOTAUTH、解釈できない TSIG は FORMERR。 */
int process_dns_query_impl_cap(const uint8_t *req, size_t req_len, uint8_t *res,
                               size_t max_res_len, size_t res_cap, const char *qname, uint16_t qtype,
                               const char *client_ip, compress_ctx_t *comp_ctx,
                               bool is_tcp, rate_limit_config_t **out_rrl_cfg,
                               zone_db_snapshot_t *snap, server_config_t *cfg,
                               zone_db_entry_t **out_matched_entry) {
  if (req_len < DNS_HEADER_SIZE) {
    return 0; // 不正な短いパケットは無応答で破棄
  }
  tsig_request_t tsig;
  tsig_check_request(cfg, req, req_len, client_ip, &tsig);
  if (tsig.status == TSIG_REQ_NONE) {
    return process_query_body(req, req_len, res, max_res_len, res_cap, qname, qtype, client_ip, comp_ctx,
                              is_tcp, out_rrl_cfg, snap, cfg, out_matched_entry, NULL);
  }
  /* TSIG RR を除き ARCOUNT を 1 減らした要求 (RFC 8945 §5.2)。解釈できない TSIG はそのまま渡す。 */
  static _Thread_local uint8_t stripped[UINT16_MAX];
  const uint8_t *body_req = req;
  size_t body_len = req_len;
  if (tsig.status != TSIG_REQ_FORMERR && tsig.stripped_len <= sizeof(stripped)) {
    memcpy(stripped, req, tsig.stripped_len);
    uint16_t arcount = (uint16_t)(((req[10] << 8) | req[11]) - 1);
    stripped[10] = (uint8_t)(arcount >> 8);
    stripped[11] = (uint8_t)(arcount & 0xFF);
    body_req = stripped;
    body_len = tsig.stripped_len;
  }
  tsig.res_limit = max_res_len;
  int ret = process_query_body(body_req, body_len, res, max_res_len, res_cap, qname, qtype, client_ip, comp_ctx,
                               is_tcp, out_rrl_cfg, snap, cfg, out_matched_entry, &tsig);
  if (ret < DNS_HEADER_SIZE) return ret;
  size_t limit = tsig.res_limit;
  if (res_cap != 0 && limit > res_cap) limit = res_cap;
  return tsig_finish_response(res, (size_t)ret, limit, &tsig);
}

static int process_query_body(const uint8_t *req, size_t req_len, uint8_t *res,
                              size_t max_res_len, size_t res_cap, const char *qname, uint16_t qtype,
                              const char *client_ip, compress_ctx_t *comp_ctx,
                              bool is_tcp, rate_limit_config_t **out_rrl_cfg,
                              zone_db_snapshot_t *snap, server_config_t *cfg,
                              zone_db_entry_t **out_matched_entry, tsig_request_t *tsig) {
  char current_qname[DNS_NAME_TEXT_SIZE];
  strlcpy(current_qname, qname, sizeof(current_qname));
  char current_qname_lc[DNS_NAME_TEXT_SIZE];
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
      // R-32: 子ゾーン頂点への DS は親ゾーンで答える (QUERY のみ)。RRL、統計、wire キャッシュもこのゾーンを使う。
      db_entry = find_zone_for_query(view, current_qname, ((req[2] >> 3) & 0x0F) == 0 ? qtype : 0);
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
  if (parse_edns_opt(req, req_len, qdcount, ancount_req, nscount_req, arcount_req, &edns) < 0) {
    /* OPT 自体が使えない (所有者名が root でない、追加セクション以外、複数、RDATA 切れ): OPT なしの FORMERR */
    return dns_build_error_response(req, req_len, res, max_res_len, 1, 0, 0, NULL, is_tcp, cfg);
  }
  edns.ede_count = 0; // 反射防止
  /* R-13: ecs-enable no のサーバーは ECS を実装していないものとして扱い、オプションを無視する
   * (AUDIT_FINDINGS §8 の決定。RFC 6891 §6.1.2: 知らないオプションは無視する)。 */
  if (edns.has_malformed_ecs && !(cfg && cfg->ecs_enable)) edns.has_malformed_ecs = false;
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

  /* RFC 8945 §5.2: 解釈できない TSIG は FORMERR (TSIG なし)。鍵・MAC・時刻・切り詰めのエラーは
   * NOTAUTH で、TSIG は process_dns_query_impl_cap() が付ける (§5.3.2)。どちらも要求の中身は処理しない。 */
  if (tsig && (tsig->status == TSIG_REQ_FORMERR || tsig->status == TSIG_REQ_ERROR)) {
    uint8_t rc = 1; // FORMERR
    if (tsig->status == TSIG_REQ_ERROR) {
      rc = 9;       // NOTAUTH
      add_ede(&edns, send_ede, 18, "Invalid TSIG");
    }
    int len = dns_build_error_response(req, req_len, res, max_res_len, rc, 0, qdcount == 1 ? 1 : 0, &edns, is_tcp, cfg);
    uint8_t op = (req[2] >> 3) & 0x0F;
    if (len >= DNS_HEADER_SIZE && (op == 4 || op == 5)) res[2] &= ~0x01; // NOTIFY/UPDATE: RD=0 (RFC 1996 §3.7、RFC 2136 §3.8)
    return len;
  }
  
  if (!cfg_for_ede || !cfg_for_ede->rfc10029_mqtype_enable) {
    edns.has_mqtype_query = false;
    edns.saw_invalid_mqtype_response_in_query = false;
    edns.mqtype_query_duplicated = false;
    edns.mqtype_count = 0;
  }

  if (edns.saw_invalid_mqtype_response_in_query || edns.mqtype_query_duplicated) {
    return dns_build_error_response(req, req_len, res, max_res_len, 1, 0, 0, &edns, is_tcp, cfg); // FORMERR
  }

  if (edns.present && edns.version > 0) {
    // RFC 6891 §6.1.3: 応答にはサーバーがサポートする最大のバージョン(0)をセットする。
    // オプションの意味はバージョンごとに決まるので、オプションの不正より先に BADVERS を返す。
    edns.version = 0;
    // rcode_ext = 1 (1 << 4 | Base 0 = 16 = BADVERS)
    return dns_build_error_response(req, req_len, res, max_res_len, 0, 1, qdcount, &edns, is_tcp, cfg);
  }

  /* 長さが不正な COOKIE (RFC 7873 §5.2.2)、不正な ECS (RFC 7871 §6、§7.2.1) は FORMERR。
   * RFC 6891 §7: オプションの不正による FORMERR には OPT を付ける (R-13)。 */
  if (edns.has_malformed_cookie || edns.has_malformed_ecs) {
    return dns_build_error_response(req, req_len, res, max_res_len, 1, 0, qdcount, &edns, is_tcp, cfg);
  }

  uint8_t opcode = (req[2] >> 3) & 0x0F;
  if (opcode != 0 && opcode != 4 && opcode != 5) {
    add_ede(&edns, send_ede, 21, "This opcode is not supported by this server");
    return dns_build_error_response(req, req_len, res, max_res_len, 4, 0, qdcount, &edns, is_tcp, cfg); // NOTIMP
  }

  // RFC 9619: OPCODE=0(QUERY) allows QDCOUNT 0 or 1; only QDCOUNT>1 is FORMERR.
  // OPCODE=4(NOTIFY)/5(UPDATE) still require QDCOUNT==1.
  bool qdcount_invalid = (opcode == 0) ? (qdcount > 1) : (qdcount != 1);
  if (qdcount_invalid) {
    add_ede(&edns, send_ede, 0, NULL);
    return dns_build_error_response(req, req_len, res, max_res_len, 1, 0, qdcount, &edns, is_tcp, cfg); // FORMERR
  }

  // RFC 9619: QDCOUNT=0 QUERY – no question section, return minimal response.
  if (opcode == 0 && qdcount == 0) {
    if (edns.has_mqtype_query) {
      // RFC 10029 §3.3: MQTYPE-Query option in a query with QDCOUNT=0 MUST be FORMERR.
      // RFC 6891 §7: オプションに起因する FORMERR には OPT を付ける。
      return dns_build_error_response(req, req_len, res, max_res_len, 1, 0, 0, &edns, is_tcp, cfg);
    }
    dns_init_response_header(res, req, 0, false); // NOERROR
    res[4] = 0; res[5] = 0; // QDCOUNT=0
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
        /* R-12: 要求の本体は返さず質問セクションで切り、OPT と EDE 21 (RFC 8914 §4.22) を付ける。
         * RD=0 (RFC 1996 §3.7、RFC 2136 §3.8)。 */
        add_ede(&edns, send_ede, 21, "NOTIFY and UPDATE are not supported for this zone type");
        int len = dns_build_error_response(req, req_len, res, max_res_len, 4, 0, qdcount, &edns, is_tcp, cfg);
        res[2] &= ~0x01;
        return len;
      }
    }
    if (edns.has_mqtype_query) {
      // RFC 10029 §3.3: QUERY 以外への MQTYPE-Query は FORMERR。RFC 6891 §7: OPT を付ける。
      int len = dns_build_error_response(req, req_len, res, max_res_len, 1, 0, qdcount, &edns, is_tcp, cfg);
      res[2] &= ~0x01;
      return len;
    }
    /* R-30: TSIG は process_dns_query_impl_cap() で検証済み (RFC 8945 §5.2)。ここに来るのは TSIG なしか
     * 検証できた要求だけで、応答の署名もそこで行う。受け付けるのは masters からの NOTIFY で、
     * tsig-key を設定したゾーンではその鍵で署名されたものだけ。それ以外は方針による拒否 (REFUSED)。 */
    tsig_key_t *tkey = (tsig && tsig->status == TSIG_REQ_VALID) ? tsig->key : NULL;
    bool auth = false;
    if (db_entry && view) {
      zone_config_t *zcfg = find_zone_config_in_view(cfg, view->name, db_entry->domain);
      if (zcfg && zcfg->masters_count > 0) {
        bool from_master = false;
        for (int k = 0; k < zcfg->masters_count; k++) {
          if (zcfg->masters_parsed ? cidr_entry_match_str(&zcfg->masters_parsed[k], client_ip)
                                   : match_cidr(client_ip, zcfg->masters[k].ip)) {
            from_master = true;
            break;
          }
        }
        bool key_ok = !(zcfg->tsig_key && zcfg->tsig_key[0] != '\0') ||
                      (tkey && tsig_key_names_equal(tkey->name, zcfg->tsig_key));
        auth = from_master && key_ok;
      }
    }

    uint8_t notify_rcode = 0;
    if (auth) {
      atomic_store_explicit(&db_entry->refresh_now, true, memory_order_release);
      if (g_control_kq != -1) {
        struct kevent ev;
        EV_SET(&ev, 2, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
        kevent(g_control_kq, &ev, 1, NULL, 0, NULL);
      }
    } else {
      notify_rcode = 5; // REFUSED
      add_ede(&edns, send_ede, 18, "Query refused due to access control");
    }
    int offset = dns_build_error_response(req, req_len, res, max_res_len, notify_rcode, 0, qdcount,
                                      &edns, is_tcp, cfg);
    /* RFC 1996 §4.7: 受け付けた NOTIFY への応答は flags QR AA、RD=0 (§3.7)。
     * 拒否した NOTIFY はゾーンの権威として答えていないので AA=0 (R-06)。 */
    res[2] &= ~0x01;
    if (auth) res[2] |= 0x04;
    return offset;
  }

  if (opcode == 5) { // UPDATE
    if (db_entry && view) {
      server_config_t *cfg_chk = cfg;
      zone_config_t *zc = find_zone_config_in_view(cfg_chk, view->name, db_entry->domain);
      if (zc && zc->type && (strcasecmp(zc->type, "program") == 0 ||
                              strcasecmp(zc->type, "forward") == 0)) {
        /* R-12: 要求の本体は返さず質問セクションで切り、OPT と EDE 21 (RFC 8914 §4.22) を付ける。
         * RD=0 (RFC 1996 §3.7、RFC 2136 §3.8)。 */
        add_ede(&edns, send_ede, 21, "NOTIFY and UPDATE are not supported for this zone type");
        int len = dns_build_error_response(req, req_len, res, max_res_len, 4, 0, qdcount, &edns, is_tcp, cfg);
        res[2] &= ~0x01;
        return len;
      }
    }
    if (edns.has_mqtype_query) {
      // RFC 10029 §3.3: QUERY 以外への MQTYPE-Query は FORMERR。RFC 6891 §7: OPT を付ける。
      int len = dns_build_error_response(req, req_len, res, max_res_len, 1, 0, qdcount, &edns, is_tcp, cfg);
      res[2] &= ~0x01;
      return len;
    }
    /* RFC 2136 §3.1.1, §3.1.2: ZTYPE が SOA でなければ FORMERR。ZNAME と ZCLASS がこのサーバー
     * (クライアントのビュー) のゾーンでなければ NOTAUTH。どちらも権限の確認 (§3.3) より前に行う。
     * ZOCOUNT (QDCOUNT) != 1 は上で FORMERR にしている。上位のゾーンに一致しただけのときも NOTAUTH。*/
    int zone_rcode = 0;
    size_t zone_end = get_question_end_offset(req, req_len, 1);
    uint16_t zclass = (zone_end >= DNS_HEADER_SIZE + 5)
                          ? (uint16_t)((req[zone_end - 2] << 8) | req[zone_end - 1]) : 0;
    if (qtype != 6) {
      zone_rcode = 1; // FORMERR
    } else if (!db_entry || !view || zclass != 1 || !domain_names_match_ci(db_entry->domain, current_qname)) {
      zone_rcode = 9; // NOTAUTH
    }
    /* R-30: TSIG は process_dns_query_impl_cap() で検証済み (RFC 8945 §5.2)。ここに来るのは TSIG なしか
     * 検証できた要求だけ。allow-update はアドレスが一致するか、検証できた鍵の名前が書かれていれば許可
     * (BIND と同じく、アドレスで許可されたクライアントの署名付き要求も受け付ける)。
     * 許可されない更新は REFUSED (RFC 2136 §3.3)。署名は呼び出し側で付ける。 */
    tsig_key_t *tkey = (tsig && tsig->status == TSIG_REQ_VALID) ? tsig->key : NULL;
    bool auth = false;
    bool zone_is_master = false;
    if (zone_rcode == 0) {
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
        for (int i = 0; !auth && tkey && i < zcfg->allow_update_count; i++) {
          if (tsig_key_names_equal(tkey->name, zcfg->allow_update[i])) auth = true;
        }
      }
    }

    int rcode = 5; // REFUSED
    if (zone_rcode != 0) {
      rcode = zone_rcode;
    } else if (!zone_is_master) {
      /* RFC 2136 §3.1.2 はセカンダリに UPDATE をプライマリへ転送させる (§6)。KariDNS は転送しない
       * ので、方針による拒否 (RFC 1035 §4.1.1 REFUSED) を返す。allow-update を満たしていても同じ。*/
      add_ede(&edns, send_ede, 18, "Updates are not accepted for a secondary zone");
    } else if (auth) {
      rcode = handle_dynamic_update(req, req_len, db_entry, client_ip, tkey ? tkey->name : "<none>");
    } else {
      add_ede(&edns, send_ede, 18, "Query refused due to access control");
    }

    /* RFC 2136 §3.8: ID と OPCODE を写し、ゾーンセクション以外のセクションは返さない (カウント 0)。
     * QR=1、RD=0 (§2.2 / §3.8)。AA は UPDATE 応答では意味を持たないので 0。 */
    int offset = dns_build_error_response(req, req_len, res, max_res_len, (uint8_t)(rcode & 0x0F), 0, qdcount,
                                      &edns, is_tcp, cfg);
    res[2] &= ~0x01;
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
      /* UDP 応答の上限はクライアントが OPT で通知したサイズ (512 以上に丸め、サーバーの
       * udp-bufsize 以下。RFC 6891 §6.2.3、§6.2.5)。呼び出し側の max_res_len が大きくても小さくても
       * 置き換える (以前は 512 ちょうどのとき呼び出し側の値のままで、非同期経路では 4096 まで
       * 返しえた)。呼び出し側が 512 未満の小さなバッファを渡したときは広げない (res[] の範囲外へ
       * 書き込むため)。res_cap が分かっていればそれを超えない。 */
      if (max_res_len >= UDP_DEFAULT_MAX_RES_LEN) {
        max_res_len = edns.udp_payload_size;
        if (res_cap != 0 && max_res_len > res_cap) max_res_len = res_cap;
      }
    }
  }
  /* RFC 8945 §5.3: 署名する応答は、上限から TSIG RR の分を空けて組み立てる (切り詰めは TC=1 で表す) */
  if (tsig) {
    tsig->res_limit = max_res_len;
    size_t reserve = tsig_response_reserve(tsig);
    if (reserve > 0 && max_res_len > reserve + DNS_HEADER_SIZE) max_res_len -= reserve;
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

  /* RFC 6891 §7: OPT 付きの問い合わせには、切り詰め (TC=1) 応答でも OPT を返す。
   * 本文 (回答・権威・追加セクション) の上限から OPT 分を先に差し引いておく。 */
  size_t body_max_len = max_res_len;
  if (edns.present) {
    size_t opt_reserve = edns_opt_reserve_len(&edns, is_tcp, cfg);
    if (max_res_len > opt_reserve + DNS_HEADER_SIZE)
      body_max_len = max_res_len - opt_reserve;
  }

  size_t q_offset = DNS_HEADER_SIZE;
  if (skip_wire_name(req, req_len, q_offset, &q_offset) != 0) {
    return -1;
  }
  if (q_offset + 4 > req_len) {
    // QTYPE/QCLASS が欠けている: 質問を区切れないので QDCOUNT=0 の FORMERR
    add_ede(&edns, send_ede, 0, NULL);
    return dns_build_error_response(req, req_len, res, max_res_len, 1, 0, 0, &edns, is_tcp, cfg);
  }
    if (db_entry) {
        time_t deadline = zone_expire_deadline(db_entry);
        if (deadline > 0 && time(NULL) > deadline) {
            bool serve_stale = (cfg_for_ede != NULL && cfg_for_ede->serve_stale);
            if (!serve_stale) {
                /* R-18: 期限切れのゾーンは答えられない。RFC 8914 §4.25 (24 Invalid Data) が
                 * 「最新のゾーンが古すぎる、または期限切れ」を例に挙げる。EDE 3 (§4.4) は古いデータで
                 * 答えたときのもので、下の serve-stale の経路だけで使う。 */
                add_ede(&edns, send_ede, 24, "Zone expired (SOA EXPIRE exceeded)");
                return dns_build_error_response(req, req_len, res, max_res_len, 2, 0, 1, &edns, is_tcp, cfg);
            } else {
                add_ede(&edns, send_ede, 3, "Stale Answer (Zone EXPIRED)");
            }
        }
    }

    uint16_t qclass = (req[q_offset + 2] << 8) | req[q_offset + 3];

    // UDP経由(is_tcp == 0)でAXFR(252)を受信した場合はRFC 5936違反のためFORMERRを返す
    if (!is_tcp && qtype == 252) {
      return dns_build_error_response(req, req_len, res, max_res_len, 1, 0, 1, &edns, is_tcp, cfg); // FORMERR
    }

    if (__builtin_expect(qclass == 1, 1)) {
      // IN class (fast path)
    } else if (qclass == 255) {
      // ANY class
    } else if (qclass == 3) {
      // CH class
    } else {
      add_ede(&edns, send_ede, 0, NULL);
      return dns_build_error_response(req, req_len, res, max_res_len, 5, 0, 1, &edns, is_tcp, cfg); // REFUSED
    }
  q_offset += 4;
  memcpy(res, req, q_offset);
  register_wire_name_for_compression(res, DNS_HEADER_SIZE, comp_ctx);
  /* R-05: RA/Z/AD/TC は問い合わせから写さない。AA=1 は権威データの応答の既定で、委任・REFUSED・
   * SERVFAIL・BADCOOKIE ではそれぞれの経路で落とす。 */
  dns_init_response_header(res, req, 0, true);
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
          view->name, zcfg->domain, req, req_len, res, max_res_len,
          res_cap != 0 ? res_cap : max_res_len, client_ip, is_tcp);
      plugin_result_len = add_opt_to_bare_passthrough(res, max_res_len, plugin_result_len,
                                                            &edns, is_tcp, cfg);

      // programゾーンも他ゾーンと同じRRL設定(out_rrl_cfgは関数冒頭で既に
      // このゾーン用に正しくセット済み)でレート制限を受けさせる。
      // *out_rrl_cfg = NULL による無効化は絶対に行わないこと
      // (スプーフィングされたUDPクエリでプラグイン呼び出しを無制限に
      //  誘発できてしまい、RRLの存在意義そのものが破られる)。
      return plugin_result_len;
    }
    if (zcfg && zcfg->type && strcasecmp(zcfg->type, "forward") == 0) {
      int fwd_len = dispatch_forward_zone(zcfg, req, req_len, res, max_res_len);
      return add_opt_to_bare_passthrough(res, max_res_len, fwd_len, &edns, is_tcp, cfg);
    }
  }

  res[6] = 0; res[7] = 0;
  res[8] = 0; res[9] = 0;
  res[10] = 0; res[11] = 0;

  if (!current_zone) {
    res[2] &= ~0x04; // R-06: 権威を持たない名前への REFUSED は AA=0 (RFC 1035 §4.1.1)
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
    res[2] &= ~0x04; // R-27: データを持たないので AA=0
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

  /* RFC 7314 §3: 権威を持つゾーンへの EXPIRE 付き問い合わせには、SOA EXPIRE (プライマリ)
   * または expire タイマーの残り (セカンダリ) を返す。権威が無い応答 (上の REFUSED) には
   * 付けない (§3.3)。値は本体に依存しないので wire キャッシュのヒット時も同じく付く。 */
  if (edns.present && edns.has_expire_query && db_entry && !is_badcookie) {
    edns.send_expire = true;
    edns.send_expire_value = zone_expire_option_value(db_entry, time(NULL));
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
    /* RFC 1995 §3: クライアントの版の SOA が Authority に無ければ FORMERR (TCP と同じ) */
    if (!ixfr_request_client_serial(req, req_len, q_offset, &client_serial))
      return dns_build_error_response(req, req_len, res, max_res_len, 1, 0, qdcount, &edns, is_tcp, cfg);

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

    /* R-15, RFC 1995 §2: 同じか新しい版 (RFC 1982) なら最新なので、TC を立てずに SOA 1件で答える */
    bool is_up_to_date = (client_serial == current_serial || serial_is_newer(client_serial, current_serial));
    if (!is_up_to_date) {
      res[2] |= 0x02; // Set TC (Truncated) bit to prompt TCP retry
    }

    if (soa_rec) {
      dns_record_t rec_copy = *soa_rec;
      if (serialize_dns_record(res, body_max_len, &offset, &rec_copy, comp_ctx, NULL, 0xFFFFFFFF) >= 0) {
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
  // DNS Cookie (RFC 7873 / RFC 9018) は応答本体に影響しないのでキャッシュを使う。Server Cookie は
  // 上で検証・生成済みで、ヒット時も assemble_edns_opt() がクエリごとに OPT へ付ける
  // (body_max_len は Cookie 分を差し引き済み)。BADCOOKIE と不正な Cookie は通常パスで処理する。
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
       !edns.has_malformed_cookie);

  if (edns_safe_for_cache && !is_badcookie && opcode == 0 && qdcount == 1 && qclass == 1 &&
      current_zone && current_zone->response_cache.buckets && max_res_len >= 512) {
    uint32_t qname_hash = calc_fnv1a_str(current_qname_lc);
    size_t hash_idx = (qname_hash ^ (uint32_t)qtype) & (current_zone->response_cache.bucket_count - 1);
    bool wc_hit = false;
    for (response_cache_entry_t *e = current_zone->response_cache.buckets[hash_idx]; e != NULL; e = e->next) {
      if (e->qtype == qtype && e->qclass == qclass && e->name_hash == qname_hash &&
          strcmp(e->name, current_qname_lc) == 0) {
        if ((size_t)q_offset + e->body_len <= body_max_len) {
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
      // RFC 10029 §3.3 / RFC 6891 §7: FORMERR (OPT 付き、AA=0)
      return dns_build_error_response(req, req_len, res, max_res_len, 1, 0, 1, &edns, is_tcp, cfg);
    }
    int limit = (cfg_for_ede && cfg_for_ede->max_mqtypes > 0) ? cfg_for_ede->max_mqtypes : 4;
    for (int i = 0; i < edns.mqtype_count && num_qtypes <= limit; i++) {
       uint16_t mq = edns.mqtypes[i];
       if (is_non_data_rrtype(mq)) {
          // RFC 10029 §3.3 / RFC 6891 §7: FORMERR (OPT 付き、AA=0)
          return dns_build_error_response(req, req_len, res, max_res_len, 1, 0, 1, &edns, is_tcp, cfg);
       }
       bool dup = false;
       for (int j = 0; j < num_qtypes; j++) { if (qtypes[j] == mq) { dup = true; break; } }
       if (dup) {
          // RFC 10029 §3.3 / RFC 6891 §7: FORMERR (OPT 付き、AA=0)
          return dns_build_error_response(req, req_len, res, max_res_len, 1, 0, 1, &edns, is_tcp, cfg);
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
  resolve_name(current_qname, qclass, qtypes, num_qtypes, &db_entry, &current_zone, res, body_max_len,
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
  return process_dns_query_cap(req, req_len, res, max_res_len, 0, qname, qtype, client_ip, comp_ctx,
                               is_tcp, out_rrl_cfg, snap);
}

int process_dns_query_cap(const uint8_t *req, size_t req_len, uint8_t *res,
                          size_t max_res_len, size_t res_cap, const char *qname, uint16_t qtype,
                          const char *client_ip, compress_ctx_t *comp_ctx,
                          bool is_tcp, rate_limit_config_t **out_rrl_cfg,
                          zone_db_snapshot_t *snap) {
  server_config_t *cfg = acquire_config_snapshot();
  zone_db_entry_t *matched_entry = NULL;
  int ret = process_dns_query_impl_cap(req, req_len, res, max_res_len, res_cap, qname, qtype,
                                       client_ip, comp_ctx, is_tcp, out_rrl_cfg, snap, cfg, &matched_entry);
  release_config_snapshot(cfg);
  if (ret >= DNS_HEADER_SIZE && matched_entry) {
    uint8_t rcode = res[3] & 0x0F;
    uint16_t ancount = ((uint16_t)res[6] << 8) | (uint16_t)res[7];
    record_observatory_response(matched_entry, rcode, ancount);
  }
  return ret;
}

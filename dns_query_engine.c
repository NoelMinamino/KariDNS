#define OPENSSL_SUPPRESS_DEPRECATED 1
#include "dns_query_engine.h"
#include "dns_server_internal.h"
#include "dns_log.h"
#include "dns_catalog_zone.h"
#include "dns_dnstap.h"
#include "dns_edns_ecs.h"
#include "dns_rrl.h"
#include "dns_tsig_acl.h"
#include "dns_priv_sandbox.h"
#include "dns_dynamic_update.h"
#include "dns_siphash.h"
#include "dns_zone_image.h"
#include "dns_alias.h"

#ifdef __FreeBSD__
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/procdesc.h>
#endif

#define STATIC_TEST

/* 名前解決が CNAME/DNAME で別のゾーンに移ったか (共有の応答キャッシュの鍵は最初のゾーンの版だけ
 * なので、移った応答は入れない: 移り先のゾーンが更新されても古い応答を返し続けてしまう) */
static _Thread_local bool t_resolve_crossed_zone;
/* 応答の大きさの上限で Additional を途中で打ち切ったか (TC は立てない、RFC 2181 §9)。キャッシュの鍵は
 * 問い合わせの受信バッファの大きさを含まないので、打ち切った応答は入れない */
static _Thread_local bool t_resolve_additional_cut;
/* C1: the Additional section holds (or looked for) glue of a sibling zone (append_glue_records() step 3).  The cache key holds only the
 * first zone's data generation; a sibling's publication reaches that generation later (g_glue_dirty and the control thread) and only for
 * the first MAX_PRELINK_TARGETS targets, so such an answer is not stored. */
static _Thread_local bool t_resolve_sibling_glue;
/* B9a: the answer holds ALIAS-expanded addresses (or an ALIAS target that could not be resolved): the result changes with the resolver's TTLs, so it
 * is not stored in the shared response cache; and the SERVFAIL gets an extended error */
static _Thread_local bool t_resolve_alias_expanded;
static _Thread_local bool t_resolve_alias_failed;

/* allow-query / allow-query-on (BIND 9.20 ARM): what the ACL check needs besides the client address.  The transport sets the address
 * the query came to (query_set_local_addr()) right before it calls process_dns_query*(); the call reads it and clears it, so a caller
 * that does not set it (unit tests, fuzzers) gives "unknown".  t_qacl.key is the TSIG key the request was verified with. */
static _Thread_local struct {
  struct sockaddr_storage local;
  bool local_valid;
  struct sockaddr_storage client;   /* the client in binary, so that the check does not parse client_ip again */
  bool client_valid;
  const char *key;
} t_qacl;

static bool qacl_copy_addr(struct sockaddr_storage *dst, const void *sa) {
  if (!sa) return false;
  sa_family_t fam = ((const struct sockaddr *)sa)->sa_family;
  if (fam == AF_INET) {
    memcpy(dst, sa, sizeof(struct sockaddr_in));
  } else if (fam == AF_INET6) {
    memcpy(dst, sa, sizeof(struct sockaddr_in6));
  } else {
    return false;
  }
  return true;
}

void query_set_local_addr(const void *sa) {
  t_qacl.local_valid = qacl_copy_addr(&t_qacl.local, sa);
}

void query_set_client_addr(const void *sa) {
  t_qacl.client_valid = qacl_copy_addr(&t_qacl.client, sa);
}

/* Does allow-query / allow-query-on of the zone `entry` (of this view) let the client in?  For the zone the query was routed to the
 * caller has the configuration; a zone that a CNAME or glue lookup reaches is looked up here.  No allocation. */
static inline bool zone_query_permitted(const server_config_t *cfg, const zone_config_t *zcfg, const char *view_name, const char *client_ip) {
  if (!cfg || !cfg->acl_query_active) return true;
  return query_acl_permits_sa(cfg, zcfg, view_name, client_ip, t_qacl.client_valid ? &t_qacl.client : NULL, t_qacl.key,
                              t_qacl.local_valid ? &t_qacl.local : NULL);
}

program_plugin_t *g_program_plugins = NULL;
int g_program_plugins_count = 0;

/* S5 phase B-1: the engine reads the zone image (dns_zone_image.h), not zone_arena_t.records[]. A published version (zone_version_t) carries the image (with the zone level tables:
 * tinydns locations, tags), the response cache state and the generation. RRs are named by their index in the image. */

/* Final TTL serialize_dns_record() writes with an override: the smaller of the two (0xFFFFFFFF = no override). */
static inline uint32_t ttl_with_override(uint32_t ttl, uint32_t override_ttl) {
  return (override_ttl != 0xFFFFFFFF && override_ttl < ttl) ? override_ttl : ttl;
}

/* RRSIG RRs of the owner `name_id` that cover `type_covered`, in zone order (a key rollover leaves several, so no
 * break). owner_override is the QNAME of a wildcard expansion. false only when one does not fit. */
static bool attach_covering_rrsig_ext(const zone_image_t *img, uint32_t name_id, const char *owner_override,
                                      uint16_t type_covered, uint8_t *res, size_t max_res_len, uint16_t *offset,
                                      compress_ctx_t *comp_ctx, uint16_t *count, uint32_t override_ttl) {
  const zone_image_rr_t *rrs = zone_image_rrs(img);
  uint32_t k = zone_image_name_first_rr(img, name_id);
  uint32_t end = k + zone_image_name_rr_count(img, name_id);
  for (; k < end; k++) {
    if (rrs[k].type != 46 /* RRSIG */) continue;
    uint16_t covered;
    if (zone_image_rrsig_covered(img, k, &covered) != 0 || covered != type_covered)
      continue; // a malformed RRSIG is skipped, not fatal
    if (image_serialize_rr(img, k, res, max_res_len, offset, comp_ctx, owner_override,
                           ttl_with_override(rrs[k].ttl, override_ttl)) < 0)
      return false; // only a full buffer is reported to the caller
    (*count)++;
  }
  return true;
}

static inline bool attach_covering_rrsig(const zone_image_t *img, uint32_t name_id, const char *owner_override,
                                         uint16_t type_covered, uint8_t *res, size_t max_res_len, uint16_t *offset,
                                         compress_ctx_t *comp_ctx, uint16_t *count) {
  return attach_covering_rrsig_ext(img, name_id, owner_override, type_covered, res, max_res_len, offset, comp_ctx,
                                   count, 0xFFFFFFFF);
}

/* R-31: NSEC3 parameters of the zone's denial proofs, chosen once by build_zone_index() and kept in the image
 * (select_nsec3_params(): Flags 0, SHA-1, salt of 0-255 octets, complete chain first; RFC 5155 §4.1.2, §7.3). */
typedef struct {
  uint32_t chain;  /* chain index in the image, ZONE_IMAGE_NONE when the zone has no NSEC3 RR for the parameters */
  uint8_t algorithm;
  uint16_t iterations;
  uint8_t salt_len;
  const uint8_t *salt;
} zone_n3_t;

/* false when the zone has no usable NSEC3PARAM at apex_name: it then gives NSEC proofs (or none). */
static bool zone_nsec3(const zone_image_t *img, const char *apex_name, zone_n3_t *out) {
  if (img->n3_param_rr == ZONE_IMAGE_NONE) return false;
  if (!domain_names_match_ci(zone_image_name_text(img, zone_image_rr_name(img, img->n3_param_rr)), apex_name))
    return false;
  out->chain = img->n3_chain;
  out->algorithm = img->n3_algorithm;
  out->iterations = img->n3_iterations;
  out->salt_len = img->n3_salt_len;
  out->salt = zone_image_bytes(img, img->n3_salt_off);
  return true;
}

static bool is_non_data_rrtype(uint16_t t) {
    switch (t) {
        case 41: case 249: case 250: case 251: case 252: case 253: case 254: case 255:
            return true;
        default:
            return false;
    }
}

/* RFC 5155 §7.2.8: NSEC3 RR とそれを覆う RRSIG はハッシュ化した名前の NSEC3 チェーンのデータで、通常の
 * 名前空間の RR ではない。これしか持たない名前は (その下にも RR が無ければ) 存在しないものとして答える
 * (§7.2.2 の Name Error)。AXFR/IXFR はゾーンの全レコードを送るので、この判定を使わない。 */
static bool is_nsec3_chain_rr(const zone_image_t *img, uint32_t rr) {
  uint16_t type = zone_image_rrs(img)[rr].type;
  if (type == 50) return true;
  uint16_t covered = 0;
  return type == 46 && zone_image_rrsig_covered(img, rr, &covered) == 0 && covered == 50;
}

/* B9a (design 3.6b): PowerDNS's LUA records (TYPE 65402 of CLASS IN) are in the zone for the transfer only.  Like PowerDNS with
 * enable-lua-records=no, a query never sees them: not as an answer (not for QTYPE 65402 or ANY), and a name that holds nothing else
 * does not exist (NXDOMAIN).  KariDNS's own Extended AXFR record of the same number (CLASS 65302) is not a zone RR at all. */
static bool rr_not_served(const zone_image_t *img, uint32_t rr) {
  const zone_image_rr_t *r = &zone_image_rrs(img)[rr];
  if (r->type == DNS_TYPE_PDNS_LUA && r->class_val == 1) return true;
  return is_nsec3_chain_rr(img, rr);
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

/* RR rr は「今このクエリ時点で」応答に含めるべきかを判定する。
 * 含めるべきならtrueを返し、*effective_ttl_out に配信すべきTTLを書く
 * (通常のRRならイメージのTTLをそのままコピーするだけ)。
 * 含めるべきでなければfalseを返す(呼び出し側はこのRRを無視する)。
 *
 * tinydns の時刻・location、ECSタグ、LOCATIONタグはイメージの ext[] にあり、無いRR(制限のないRR)は
 * 即座にtrueを返す。 */
STATIC_TEST bool image_rr_currently_valid(const zone_image_t *img, uint32_t rr, time_t now,
                                          const char client_loc[2],
                                          const char *client_ecs_tag,
                                          const char *client_loc_tag,
                                          uint32_t *effective_ttl_out) {
    return zone_image_rr_valid(img, rr, now, client_loc, client_ecs_tag, client_loc_tag, effective_ttl_out);
}

/* The common case (an RR with no ext[] entry) without the call */
static inline bool rr_valid(const zone_image_t *img, uint32_t rr, time_t now, const char client_loc[2],
                            const char *client_ecs_tag, const char *client_loc_tag, uint32_t *effective_ttl_out) {
    if (zone_image_rrs(img)[rr].ext_idx == 0) {
        *effective_ttl_out = zone_image_rr_ttl(img, rr);
        return true;
    }
    return image_rr_currently_valid(img, rr, now, client_loc, client_ecs_tag, client_loc_tag, effective_ttl_out);
}

/* RDATA decoded as text for CNAME/DNAME/NS targets. A raw RR (generic_data) has no fields in the builder, so it
 * has no target here either. */
static inline bool rr_target_text(const zone_image_t *img, uint32_t rr, char *buf, size_t cap) {
  if (zone_image_rrs(img)[rr].flags & ZONE_IMAGE_RR_RAW) return false;
  return zone_image_rr_target(img, rr, buf, cap) == 0;
}

/* Additional セクションに載せる名前 (MX/SRV/NS のターゲット) を glue に加える。同じ名前は 1 回だけ、16 個まで。 */
STATIC_TEST void collect_additional_rr_glue(const zone_image_t *img, uint32_t rr, glue_list_t *glue) {
  if (!img || !glue || glue->minimal) return;
  uint16_t t = zone_image_rr_type(img, rr);
  // MX (RFC 1035 §3.3.9), SRV (RFC 2782), NS: the target is the first name after the fixed fields
  if (t != 15 && t != 33 && t != 2) return;
  char target[DNS_NAME_TEXT_SIZE];
  if (!rr_target_text(img, rr, target, sizeof(target))) return; // a decoded name is never empty (the root is ".")

  for (int k = 0; k < glue->count; k++) {
    if (strcasecmp(glue->targets[k], target) == 0) {
      return;
    }
  }
  if (glue->count < 16) {
    strlcpy(glue->targets[glue->count++], target, sizeof(glue->targets[0]));
  }
}

/* 応答に載せるRRの絞り込み条件 (tinydns の location / 時刻、ECS / location タグ)。answer_scope が
 * NULL でなければ、見たRRごとに note_ecs_variant() で ECS SCOPE を記録する (Answer セクション用)。 */
typedef struct {
  const char *client_loc;     /* char[2] */
  const char *client_ecs_tag;
  const char *client_loc_tag;
  uint8_t zone_scope;
  uint8_t *answer_scope;
} rr_filter_t;

enum { RRSIG_NONE, RRSIG_REQUIRED, RRSIG_OPTIONAL };

static inline void note_ecs_variant(const zone_image_t *img, uint32_t rr, uint16_t qtype, uint8_t zone_scope,
                                    uint8_t *answer_scope);

/* O-16 / R-03: 1 つの RRset (owner と type が同じRR全部) を書き、続けてその RRSIG を書く。
 * RRset のRRは隣り合わせにし、RRSIG を途中に挟まない (RFC 2181 §5、BIND/Unbound と同じ並び)。
 * name_id は owner のイメージ上の番号 (ZONE_IMAGE_NONE なら RRset は無い)、owner_override は
 * ワイルドカード展開のときの QNAME。
 * - RRset が入りきらない: RRset を丸ごと取り消して -1 (RFC 2181 §9: RRset の一部だけを返さない。呼び出し側で TC)。
 * - RRSIG が入りきらない: RRSIG だけ取り消す。rrsig_mode が RRSIG_REQUIRED (Answer / Authority) なら -1
 *   (RFC 4035 §3.1.1: TC を立てる)、RRSIG_OPTIONAL (Additional) なら RRset を残して成功扱い
 *   (§3.1.1: "MUST NOT set the TC bit solely because these RRSIG RRs didn't fit")。
 * 戻り値は書いたRR数 (有効なRRが無ければ 0)。 */
static int emit_rrset(const zone_image_t *img, uint32_t name_id, const char *owner_override, uint16_t type,
                      uint16_t qclass, const rr_filter_t *f, int rrsig_mode, uint8_t *res, size_t max_res_len,
                      uint16_t *offset, compress_ctx_t *comp_ctx, uint16_t *count, glue_list_t *glue) {
  if (name_id == ZONE_IMAGE_NONE) return 0;
  uint16_t start_offset = *offset, start_count = *count;
  time_t now = (img->flags & ZONE_IMAGE_F_TINYDNS) ? time(NULL) : 0;
  const zone_image_rr_t *rrs = zone_image_rrs(img);
  int written = 0;
  uint32_t k = zone_image_name_first_rr(img, name_id);
  uint32_t end = k + zone_image_name_rr_count(img, name_id);
  for (; k < end; k++) {
    if (rrs[k].type != type) continue;
    if (rr_not_served(img, k)) continue; // RFC 5155 §7.2.8 / LUA: 否定の証明でだけ書く (attach_nsec3_record)
    if (qclass != 255 && qclass != rrs[k].class_val) continue;
    if (f->answer_scope) note_ecs_variant(img, k, type, f->zone_scope, f->answer_scope);
    uint32_t eff_ttl;
    if (!rr_valid(img, k, now, f->client_loc, f->client_ecs_tag, f->client_loc_tag, &eff_ttl))
      continue;
    if (image_serialize_rr(img, k, res, max_res_len, offset, comp_ctx, owner_override, eff_ttl) < 0) {
      *offset = start_offset;
      *count = start_count;
      return -1;
    }
    (*count)++;
    written++;
    if (glue) collect_additional_rr_glue(img, k, glue);
    /* B8t-1: a zone with restricted SOA RRs answers with the first SOA the client sees, never with several (as tinydns does, djbdns 1.05;
     * RFC 2181 §6.1: one SOA per zone) */
    if (type == 6 && (img->flags & ZONE_IMAGE_F_SOA_ATTR)) break;
  }
  if (written == 0 || rrsig_mode == RRSIG_NONE || type == 46) return written;
  uint16_t rrset_offset = *offset, rrset_count = *count;
  if (!attach_covering_rrsig(img, name_id, owner_override, type, res, max_res_len, offset, comp_ctx, count)) {
    *offset = rrset_offset;
    *count = rrset_count;
    if (rrsig_mode == RRSIG_REQUIRED) return -1;
  }
  return written;
}

/* R-03: name はこのゾーンの権威データか。頂点より下の名前 (name 自身を含む) に NS RRset があれば、そこはゾーン
 * カットで、name はグルー (権威データではなく署名されない。RFC 4035 §2.2、RFC 1034 §4.2.1)。 */
static bool name_is_authoritative(const zone_image_t *img, const char *name, const char *apex) {
  if (!domain_name_is_at_or_below(name, apex)) return false;
  for (const char *n = name; n && *n && !domain_names_match_ci(n, apex);) {
    uint32_t id = zone_image_find_name(img, n);
    if (id != ZONE_IMAGE_NONE &&
        zone_image_rrset_next(img, id, 2, zone_image_name_first_rr(img, id)) != ZONE_IMAGE_NONE)
      return false;
    n = strchr_unescaped(n, '.');
    if (n) n++;
  }
  return true;
}

/* target (イメージ上の番号 id) の A と AAAA を Additional セクションに書く (RRset ごとに、A の後に AAAA)。
 * DO=1 で target がこのゾーンの権威データなら RRSIG も付ける (R-03、RFC 4035 §3.1.1。入りきらなければ
 * RRSIG だけ落とし TC は立てない)。戻り値: 書いたRR数、入りきらなければ -1。 */
static int append_additional_from_zone(const zone_image_t *img, const char *apex, const char *target, uint32_t id,
                                        bool dnssec_ok, const rr_filter_t *f, uint8_t *res, size_t max_res_len,
                                        uint16_t *offset, compress_ctx_t *comp_ctx, uint16_t *arcount) {
  if (id == ZONE_IMAGE_NONE) return 0;
  int mode = (dnssec_ok && name_is_authoritative(img, target, apex)) ? RRSIG_OPTIONAL : RRSIG_NONE;
  static const uint16_t types[2] = { 1, 28 };
  int total = 0;
  for (int t = 0; t < 2; t++) {
    int w = emit_rrset(img, id, NULL, types[t], 255, f, mode, res, max_res_len, offset, comp_ctx, arcount, NULL);
    if (w < 0) return -1;
    total += w;
  }
  return total;
}

/* Additional-section addresses ignore ECS data (RFC 7871 §7.4: "Addresses in the Additional section SHOULD therefore ignore ECS
 * data"; §7.3.1: a resolver does not tie them to a network, so a tailored address would be cached for every client): the records
 * are chosen as for a query without ECS, i.e. only the ones without an ECS tag ($ECS-SUBNET default / none).  Location tags and
 * tinydns locations come from the client's own address and still apply. */
STATIC_TEST bool append_glue_records(const zone_image_t *img, const char *target,
                                     const char *zone_apex, uint8_t *res,
                                     size_t max_res_len, uint16_t *offset,
                                     compress_ctx_t *comp_ctx, uint16_t *arcount,
                                     const char client_loc[2],
                                     const char *client_loc_tag,
                                     additional_from_auth_t policy,
                                     const glue_sibling_ctx_t *sib_ctx, bool dnssec_ok) {

  if (!img || !target || policy == ADDITIONAL_AUTH_NO) return true;
  uint32_t id = zone_image_find_name(img, target);

  // 1. Fast path: the prelinked glue (zone_glue_track_build(): this zone's own A/AAAA of a NS/MX/SRV target,
  //    the RRs in zone order). It carries no RRSIGs, so DO=1 takes the lookup below (R-03).
  if (!dnssec_ok && id != ZONE_IMAGE_NONE && (zone_image_name_flags(img, id) & ZONE_IMAGE_NAME_GLUE) &&
      (policy != ADDITIONAL_AUTH_IN_DOMAIN || domain_name_is_at_or_below(target, zone_apex))) {
    time_t tinydns_now = (img->flags & ZONE_IMAGE_F_TINYDNS) ? time(NULL) : 0;
    uint16_t start_offset = *offset, start_arcount = *arcount;
    const zone_image_rr_t *rrs = zone_image_rrs(img);
    uint32_t k = zone_image_name_first_rr(img, id);
    uint32_t end = k + zone_image_name_rr_count(img, id);
    int linked = 0;
    for (; k < end; k++) {
      if (rrs[k].type != 1 && rrs[k].type != 28) continue;
      if (++linked > 32) break; // MAX_MATCH_RECS of zone_glue_track_build()
      uint32_t eff_ttl;
      if (!rr_valid(img, k, tinydns_now, client_loc, NULL, client_loc_tag, &eff_ttl)) continue;
      if (image_serialize_rr(img, k, res, max_res_len, offset, comp_ctx, NULL, eff_ttl) < 0) {
        // RFC 2181 §9: この名前のアドレスは一部だけ残さない
        *offset = start_offset;
        *arcount = start_arcount;
        return false;
      }
      (*arcount)++;
    }
    return true;
  }

  rr_filter_t f = { client_loc, NULL, client_loc_tag, 0, NULL };

  // 2. In-zone search (covers in-domain glue and out-of-zone glue in this zone)
  if (policy == ADDITIONAL_AUTH_IN_DOMAIN && !domain_name_is_at_or_below(target, zone_apex)) {
    return true;
  }

  int w = append_additional_from_zone(img, zone_apex, target, id, dnssec_ok, &f, res, max_res_len, offset,
                                      comp_ctx, arcount);
  if (w < 0) return false;
  if (w > 0) return true;

  // 3. Fallback: Search sibling authoritative zones in view dynamically if policy == ADDITIONAL_AUTH_YES
  if (policy == ADDITIONAL_AUTH_YES && sib_ctx && sib_ctx->view) {
    zone_db_entry_t *sib_entry = find_zone_in_view(sib_ctx->view, target);
    if (sib_entry) {
      zone_version_t *sib_arena = atomic_load_explicit(&sib_entry->rcu.active, memory_order_acquire);
      const zone_image_t *sib = sib_arena ? sib_arena->image : NULL;
      if (sib != img) t_resolve_sibling_glue = true; /* C1: the answer depends on another zone's version: not cached */
      /* allow-query of the sibling zone: no glue from a zone this client may not query */
      if (sib && sib != img && sib_ctx->cfg && sib_ctx->cfg->acl_query_active &&
          !zone_query_permitted(sib_ctx->cfg, zone_entry_config(sib_ctx->cfg, sib_entry), sib_ctx->view->name, sib_ctx->client_ip))
        return true;
      if (sib && sib != img) {
        /* C2: the sibling's records are chosen with the sibling's own tag definitions, as for a CNAME into another zone
         * (resolve_name_answer()); a sibling whose SOA this client does not see gives no glue (B8t-1).  Its view is taken
         * without ECS, as above (RFC 7871 §7.4), and the ECS SCOPE is not touched. */
        const zone_config_t *sib_zcfg = sib_ctx->cfg ? zone_entry_config(sib_ctx->cfg, sib_entry) : NULL;
        zone_image_view_t sv;
        zone_client_view(sib, sib_ctx->cfg, sib_zcfg, sib_ctx->client_ip, false, NULL, 0, &sv, NULL);
        if ((sib->flags & ZONE_IMAGE_F_SOA_ATTR) && zone_image_visible_soa(sib, &sv, NULL) == ZONE_IMAGE_NONE) return true;
        rr_filter_t sf = { sv.loc, NULL, sv.loc_tag, 0, NULL };
        if (append_additional_from_zone(sib, sib_entry->domain, target, zone_image_find_name(sib, target), dnssec_ok,
                                        &sf, res, max_res_len, offset, comp_ctx, arcount) < 0)
          return false;
      }
    }
  }

  return true;
}

STATIC_TEST bool nsec_covers_name(const zone_image_t *img, uint32_t rr, const char *name) {
  char next[DNS_NAME_TEXT_SIZE];
  if (!img || rr == ZONE_IMAGE_NONE || !name || zone_image_rr_type(img, rr) != 47 ||
      zone_image_rr_target(img, rr, next, sizeof(next)) != 0)
    return false;
  const char *owner = zone_image_name_text(img, zone_image_rr_name(img, rr));
  int cmp_wrap = compare_canonical_name(owner, next);
  if (cmp_wrap < 0) {
    return (compare_canonical_name(owner, name) <= 0 &&
            compare_canonical_name(name, next) < 0);
  } else {
    return (compare_canonical_name(owner, name) <= 0 ||
            compare_canonical_name(name, next) < 0);
  }
}

/* NSEC index built at freeze (sorted in canonical order, RFC 4034 §6.1). No linear fallback (X-22): a zone whose
 * index could not be allocated is not loaded, so a zone without the index has no NSEC RRs. Returns the NSEC RR
 * (image index) that covers name, ZONE_IMAGE_NONE if there is none. */
STATIC_TEST uint32_t find_covering_nsec(const zone_image_t *img, const char *name) {
  if (!img || !name || img->n_nsec == 0) return ZONE_IMAGE_NONE;
  uint32_t best = zone_image_nsec_floor(img, name);
  // name is strictly smaller than the first NSEC owner: the last NSEC covers it (wrap-around, RFC 4034 §4.1.1)
  uint32_t rr = zone_image_nsec_rr(img, best != ZONE_IMAGE_NONE ? best : img->n_nsec - 1);
  return nsec_covers_name(img, rr, name) ? rr : ZONE_IMAGE_NONE;
}

STATIC_TEST bool name_exists_in_zone(const zone_image_t *img, const char *name, const char client_loc[2], const char *client_ecs_tag, const char *client_loc_tag) {
  if (!img || !name || img->n_names == 0) return false;
  time_t tinydns_now = (img->flags & ZONE_IMAGE_F_TINYDNS) ? time(NULL) : 0;

  // (a) Exact match
  uint32_t id = zone_image_find_name(img, name);
  if (id != ZONE_IMAGE_NONE) {
    uint32_t k = zone_image_name_first_rr(img, id);
    uint32_t end = k + zone_image_name_rr_count(img, id);
    for (; k < end; k++) {
      if (rr_not_served(img, k)) continue; // RFC 5155 §7.2.8, LUA
      uint32_t eff_ttl;
      if (rr_valid(img, k, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &eff_ttl)) return true;
    }
  }

  // (b) Empty Non-Terminal (ENT) check: the owner that follows name in canonical order
  uint32_t floor_pos = zone_image_canon_floor(img, name, NULL);
  uint32_t pos = floor_pos == ZONE_IMAGE_NONE ? 0 : floor_pos + 1;
  if (pos >= zone_image_canon_count(img)) return false;

  // 正規順序で name の次に来る名前が name の下にあれば、name は空の非終端 (ENT)
  const char *rn = zone_image_name_text(img, zone_image_canon_name(img, pos));
  return domain_name_is_at_or_below(rn, name) && !domain_names_match_ci(rn, name);
}

STATIC_TEST const char *find_closest_encloser(const zone_image_t *img, const char *qname, const char *zone_apex, const char client_loc[2], const char *client_ecs_tag, const char *client_loc_tag) {
  if (!img || !qname || !zone_apex || img->n_names == 0)
    return zone_apex;
  const char *parent = qname;
  while ((parent = strchr_unescaped(parent, '.')) != NULL) {
    parent++;
    if (*parent == '\0') break;

    if (domain_names_match_ci(parent, zone_apex))
      return zone_apex;
    if (!domain_name_is_at_or_below(parent, zone_apex))
      break; // Outside zone apex

    if (name_exists_in_zone(img, parent, client_loc, client_ecs_tag, client_loc_tag)) {
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
 * the NSEC3PARAM the zone's proofs use. The chain is sorted in hash order (zone_image_freeze()), so both lookups
 * are binary searches (R-34); a zone without a chain for these parameters has no usable NSEC3 RR. `chain` is the
 * chain index (zone_n3_t.chain, ZONE_IMAGE_NONE: none). Both return an RR (image index) or ZONE_IMAGE_NONE. */
STATIC_TEST uint32_t find_matching_nsec3(const zone_image_t *img, uint32_t chain, const char *hash_b32,
                                         const char *apex) {
    if (!img || chain == ZONE_IMAGE_NONE || !hash_b32 || !apex) return ZONE_IMAGE_NONE;
    size_t tlen = strlen(hash_b32);
    uint32_t count = zone_image_n3chain(img, chain)->count;
    for (uint32_t i = zone_image_n3chain_lower_bound(img, chain, hash_b32, tlen); i < count; i++) {
        size_t hlen;
        const char *owner = zone_image_n3chain_hash(img, chain, i, &hlen);
        if (hlen != tlen || strncasecmp(owner, hash_b32, tlen) != 0) break;
        /* RFC 5155 §3: the owner is the hashed label directly below the zone apex. */
        if (domain_names_match_ci(owner + hlen + 1, apex)) return zone_image_n3chain_rr(img, chain, i);
    }
    return ZONE_IMAGE_NONE;
}

STATIC_TEST uint32_t find_covering_nsec3(const zone_image_t *img, uint32_t chain, const char *target_hash) {
    if (!img || chain == ZONE_IMAGE_NONE || !target_hash) return ZONE_IMAGE_NONE;
    uint32_t count = zone_image_n3chain(img, chain)->count;
    if (count == 0) return ZONE_IMAGE_NONE;
    /* RFC 5155 §3.1.7: the covering RR is the last one in hash order whose owner hash is below the target; below
     * the first owner, the last RR of the chain covers the target (its next hash wraps to the first owner). */
    uint32_t i = zone_image_n3chain_lower_bound(img, chain, target_hash, strlen(target_hash));
    uint32_t idx = i > 0 ? i - 1 : count - 1;
    uint32_t rr = zone_image_n3chain_rr(img, chain, idx);
    size_t hlen;
    const char *owner = zone_image_n3chain_hash(img, chain, idx, &hlen);
    char owner_hash[64];
    if (hlen >= sizeof(owner_hash)) return ZONE_IMAGE_NONE;
    memcpy(owner_hash, owner, hlen);
    owner_hash[hlen] = '\0';
    /* the next hashed owner is raw octets in the RDATA (RFC 5155 §3.2); the hash labels are base32hex (§3.3) */
    zone_image_nsec3_t v;
    char next_hash[512];
    if (zone_image_nsec3(img, rr, &v) != 0 || v.next_len == 0 || v.next_len > 255) return ZONE_IMAGE_NONE;
    dns_base32hex_encode(v.next, v.next_len, next_hash, sizeof(next_hash));
    return nsec3_covers_hash(owner_hash, next_hash, target_hash) ? rr : ZONE_IMAGE_NONE;
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
 * (tinydns の有効期限による値。0xFFFFFFFF ならRRの TTL)。false = 入りきらない: 呼び出し側は証明を
 * 取り消して TC を立てる (RFC 4035 §3.1.1、§3.1.3)。attached[] は書いたRR (イメージ内のアドレスで区別する)。 */
static bool attach_denial_record(const zone_image_t *img, uint32_t rr, uint32_t ttl,
                                 uint8_t *res, size_t max_res_len, uint16_t *offset,
                                 compress_ctx_t *comp_ctx, uint16_t *nscount,
                                 const zone_image_rr_t **attached, int *attached_count) {
    if (rr == ZONE_IMAGE_NONE) return true;
    const zone_image_rr_t *key = &zone_image_rrs(img)[rr];
    for (int i = 0; i < *attached_count; i++) {
        if (attached[i] == key) return true;
    }
    if (*attached_count < 8) attached[(*attached_count)++] = key;

    if (image_serialize_rr(img, rr, res, max_res_len, offset, comp_ctx, NULL,
                           ttl != 0xFFFFFFFF ? ttl : key->ttl) < 0) {
        return false;
    }
    (*nscount)++;
    return attach_covering_rrsig(img, key->name_id, NULL, key->type, res, max_res_len, offset, comp_ctx, nscount);
}

STATIC_TEST bool attach_nsec3_record(const zone_image_t *img, uint32_t rr,
                                uint8_t *res, size_t max_res_len, uint16_t *offset,
                                compress_ctx_t *comp_ctx, uint16_t *nscount,
                                const zone_image_rr_t **attached, int *attached_count) {
    return attach_denial_record(img, rr, 0xFFFFFFFF, res, max_res_len, offset, comp_ctx, nscount,
                                attached, attached_count);
}

/* 委任 (referral) の応答を作る。qname から apex の手前まで順に、NS RRset のある名前 (ゾーンカット) を探し、
 * あれば Authority に NS、DS または DS の不在の証明、Additional にグルーを書いて true を返す。 */
STATIC_TEST bool find_delegation(const zone_image_t *img, const char *qname,
                            const char *zone_apex, uint8_t *res,
                            size_t max_res_len, uint16_t *offset,
                            compress_ctx_t *comp_ctx, uint16_t *nscount,
                            uint16_t *arcount, bool is_ds_query,
                            const char client_loc[2],
                            const char *client_ecs_tag,
                            const char *client_loc_tag,
                            additional_from_auth_t policy,
                            const glue_sibling_ctx_t *sib_ctx,
                            bool dnssec_ok) {
  if (!img || img->n_names == 0)
    return false;
  /* E3: no owner below the apex has an NS RR: there is no zone cut to find, so skip the hash lookup per label */
  if (!(img->flags & ZONE_IMAGE_F_CUT))
    return false;
  time_t tinydns_now = (img->flags & ZONE_IMAGE_F_TINYDNS) ? time(NULL) : 0;
  const zone_image_rr_t *rrs = zone_image_rrs(img);
  const char *name = qname;
  while (name && *name && !domain_names_match_ci(name, zone_apex)) {
    // RFC 4035 §3.1.4.1: 委任点そのもの(name == qname)へのDSクエリは、
    // 参照応答(referral)にせず、権威応答としてフェーズ2の通常検索へ継続させる。
    uint32_t id = (is_ds_query && name == qname) ? ZONE_IMAGE_NONE : zone_image_find_name(img, name);
    if (id != ZONE_IMAGE_NONE) {
      /* the referral NS and DS go in the Authority section, which a resolver does not tie to a network (RFC 7871 §7.3.1, §7.4:
       * SCOPE 0 on delegations): they are chosen without ECS, as the Additional section (append_glue_records()) */
      rr_filter_t flt = { client_loc, NULL, client_loc_tag, 0, NULL };
      // 委任の NS は子ゾーンのデータで署名されない (RFC 4035 §2.2)。入りきらなければ NS を丸ごと外して TC。
      int ns_written = emit_rrset(img, id, NULL, 2, 255, &flt, RRSIG_NONE, res, max_res_len,
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
          int ds_written = emit_rrset(img, id, NULL, 43, 255, &flt, RRSIG_REQUIRED, res,
                                      max_res_len, offset, comp_ctx, nscount, NULL);
          if (ds_written < 0) {
            res[2] |= 0x02;
            return true;
          }
          if (ds_written == 0) {
            // Insecure Delegation: Prove non-existence of DS (RFC 4035 §3.1.4 / RFC 5155 §7.2.3)
            const zone_image_rr_t *attached[8];
            int attached_cnt = 0;
            zone_n3_t n3;
            if (!zone_nsec3(img, zone_apex, &n3)) {
              uint32_t nsec = ZONE_IMAGE_NONE;
              uint32_t nsec_ttl = 0xFFFFFFFF;
              uint32_t k = zone_image_name_first_rr(img, id);
              uint32_t end = k + zone_image_name_rr_count(img, id);
              for (; k < end; k++) {
                if (rrs[k].type == 47 /* NSEC */) {
                  if (rrs[k].rdata_len < 1) break;
                  if (!rr_valid(img, k, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &nsec_ttl)) continue;
                  nsec = k;
                  break;
                }
              }
              if (nsec == ZONE_IMAGE_NONE) {
                nsec = find_covering_nsec(img, name);
                nsec_ttl = 0xFFFFFFFF;
              }
              if (!attach_denial_record(img, nsec, nsec_ttl, res, max_res_len, offset, comp_ctx, nscount,
                                        attached, &attached_cnt)) {
                res[2] |= 0x02;
                return true;
              }
            } else {
              // NSEC3 Insecure Delegation Proof (RFC 5155 §7.2.3)
              {
                char q_hash[64];
                if (compute_nsec3_hash(name, n3.algorithm, n3.iterations, n3.salt, n3.salt_len, q_hash, sizeof(q_hash))) {
                  uint32_t m_rec = find_matching_nsec3(img, n3.chain, q_hash, zone_apex);
                  if (m_rec != ZONE_IMAGE_NONE) {
                    if (!attach_nsec3_record(img, m_rec, res, max_res_len, offset, comp_ctx, nscount, attached, &attached_cnt)) {
                      res[2] |= 0x02;
                      return true;
                    }
                  } else {
                    // Opt-Out: Next Closer covering NSEC3 and Closest Provable Encloser matching NSEC3 (RFC 5155 §7.2.3)
                    uint32_t c_rec = find_covering_nsec3(img, n3.chain, q_hash);
                    if (c_rec != ZONE_IMAGE_NONE) {
                      if (!attach_nsec3_record(img, c_rec, res, max_res_len, offset, comp_ctx, nscount, attached, &attached_cnt)) {
                        res[2] |= 0x02;
                        return true;
                      }
                    }
                    const char *encloser = find_closest_encloser(img, name, zone_apex, client_loc, client_ecs_tag, client_loc_tag);
                    if (encloser) {
                      char ce_hash[64];
                      if (compute_nsec3_hash(encloser, n3.algorithm, n3.iterations, n3.salt, n3.salt_len, ce_hash, sizeof(ce_hash))) {
                        uint32_t ce_rec = find_matching_nsec3(img, n3.chain, ce_hash, zone_apex);
                        if (ce_rec != ZONE_IMAGE_NONE) {
                          if (!attach_nsec3_record(img, ce_rec, res, max_res_len, offset, comp_ctx, nscount, attached, &attached_cnt)) {
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

        /* glue for every NS of the delegation (the NS RRs are not filtered: as before).
         * A1, RFC 9471: the glue of a name server inside the delegated zone (target at or below the cut, "in-domain") is required
         * (§3.1: MUST include all of it, else set TC=1; §3.3 the same for RFC 1034's algorithm).  The glue of the other name
         * servers (sibling, §3.2) SHOULD be included, but when it does not fit the server MAY set TC=1 and is not obliged to, and
         * RFC 2181 §9 says TC is not set merely because extra information did not fit.  So only a missing in-domain glue sets TC;
         * after the first sibling glue that does not fit no more sibling glue is added (as in the positive-answer path, Phase 10 of
         * resolve_name_answer(): the Additional section is cut there, without TC) while the in-domain glue of the later name
         * servers is still tried. */
        uint32_t k = zone_image_name_first_rr(img, id);
        uint32_t end = k + zone_image_name_rr_count(img, id);
        bool optional_full = false;
        for (; k < end; k++) {
          char target[DNS_NAME_TEXT_SIZE];
          if (rrs[k].type == 2 && rr_target_text(img, k, target, sizeof(target))) {
            bool in_domain = domain_name_is_at_or_below(target, name);
            if (!in_domain && optional_full) continue;
            if (!append_glue_records(img, target, zone_apex, res,
                                     max_res_len, offset, comp_ctx, arcount, client_loc, client_loc_tag, policy, sib_ctx,
                                     dnssec_ok)) {
              if (in_domain) {
                res[2] |= 0x02;
                return true;
              }
              optional_full = true;
            }
          }
        }
        return true;
      }
    }
    name = strchr_unescaped(name, '.');
    if (name)
      name++;
  }
  return false;
}

/* RFC 7871 §7.2.1: Answer セクションに入れる RRset にサブネット別の変種 (ECS タグ付きRR) が
 * あれば、クライアントに一致したかどうかに関係なく、応答はサブネットに依存する。そのゾーンで求めた
 * SCOPE を応答の SCOPE にする (複数の RRset や CNAME 先のゾーンがあれば最長のもの)。 */
static inline void note_ecs_variant(const zone_image_t *img, uint32_t rr, uint16_t qtype, uint8_t zone_scope,
                                    uint8_t *answer_scope) {
  const zone_image_ext_t *e = zone_image_rr_ext(img, rr);
  if (e == NULL || e->ecs_tag_off == 0) return;
  uint16_t t = zone_image_rr_type(img, rr);
  if (qtype != 255 && t != qtype && t != 5 && t != 39) return;
  if (zone_scope > *answer_scope) *answer_scope = zone_scope;
}

/* types[] にまだ無ければ t を加えて false、既にあれば true (同じ名前の RRset を 1 回だけ書くため) */
static bool rrset_type_seen(uint16_t types[64], int *count, uint16_t t) {
  for (int i = 0; i < *count; i++)
    if (types[i] == t) return true;
  if (*count < 64) types[(*count)++] = t;
  return false;
}

/* B9a (design 3.6b): the A / AAAA RRsets that the ALIAS RRs of owner `name_id` stand for, from the result table of dns_alias.c (no allocation, no
 * waiting).  qtype 1, 28 or 255 (ANY: A then AAAA).  The TTL is the smaller of the ALIAS RR's and what is left of the upstream TTL.
 * Returns the RRs written (0 = NODATA), or -1 when they do not fit (nothing is left of them: the caller sets TC); *ok_types counts the
 * (ALIAS RR, type) pairs that had a usable result: when it stays 0 the caller answers SERVFAIL (PowerDNS does when it cannot resolve). */
static int answer_alias(const zone_image_t *img, uint32_t name_id, uint64_t key, const char *owner, uint16_t qtype, uint8_t *res,
                        size_t max_res_len, uint16_t *offset, compress_ctx_t *comp_ctx, uint16_t *ancount, int *ok_types) {
  static const uint16_t types[2] = { 1, 28 };
  const zone_image_rr_t *rrs = zone_image_rrs(img);
  uint16_t start_offset = *offset, start_count = *ancount;
  int written = 0;
  *ok_types = 0;
  uint32_t k = zone_image_name_first_rr(img, name_id);
  uint32_t end = k + zone_image_name_rr_count(img, name_id);
  for (; k < end; k++) {
    if (rrs[k].type != DNS_TYPE_PDNS_ALIAS || rrs[k].class_val != 1) continue;
    uint8_t target[256];
    size_t tlen;
    if (!alias_wire_lower(zone_image_rr_rdata(img, k), zone_image_rr_rdlen(img, k), target, &tlen)) continue;
    for (int t = 0; t < 2; t++) {
      if (qtype != 255 && qtype != types[t]) continue;
      alias_answer_t a;
      if (!alias_lookup(key, target, tlen, types[t], &a)) continue;
      (*ok_types)++;
      uint32_t ttl = a.ttl < rrs[k].ttl ? a.ttl : rrs[k].ttl;
      for (uint8_t i = 0; i < a.n; i++) {
        dns_record_t r;
        memset(&r, 0, sizeof(r));
        r.name = (char *)owner;
        r.type_code = types[t];
        r.class_val = 1;
        r.ttl_value = ttl;
        r.generic_data = (uint8_t *)(uintptr_t)(a.rdata + (size_t)i * a.rdlen);
        r.generic_len = a.rdlen;
        if (serialize_dns_record(res, max_res_len, offset, &r, comp_ctx, owner, 0xFFFFFFFF) < 0) {
          *offset = start_offset;
          *ancount = start_count;
          return -1;
        }
        (*ancount)++;
        written++;
      }
    }
  }
  return written;
}

static void resolve_name_answer(const char *qname, uint16_t qclass, const uint16_t *qtypes, int num_qtypes,
                         zone_db_entry_t **db_entry_ptr,
                         zone_version_t **current_zone_ptr, uint8_t *res,
                         size_t max_res_len, uint16_t *offset,
                         compress_ctx_t *comp_ctx, uint16_t *ancount,
                         uint16_t *nscount, uint16_t *arcount,
                         int minimal_mode,
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
  char visited_qnames[16][DNS_NAME_TEXT_SIZE];
  int visited_count = 0;
  strlcpy(visited_qnames[visited_count++], current_qname, sizeof(visited_qnames[0]));
  glue_list_t glue;
  const glue_sibling_ctx_t sib_ctx = { view, cfg, client_ip };
  glue.count = 0;
  /* lib/ns/query.c ns_query_start(): an NS question always gets the NS authority and the glue, whatever minimal-responses says */
  if (num_qtypes >= 1 && qtypes[0] == 2) minimal_mode = MINIMAL_NO;
  glue.minimal = (minimal_mode == MINIMAL_YES);
  /* R-04: RRSIG 自体が要求されたとき (QTYPE RRSIG、または MQTYPE に RRSIG) は、その名前の RRSIG が全部その
   * RRset に入るので、他の RRset には付けない (同じ RRSIG を 2 回書かない。RFC 2181 §5)。 */
  bool rrsig_requested = false;
  for (int k = 0; k < num_qtypes; k++)
    if (qtypes[k] == 46) rrsig_requested = true;
  bool sign_answers = dnssec_ok && !rrsig_requested;
  bool chain_exhausted = true;
  bool any_cname_wc_expanded = false;
  char first_wc_qname[DNS_NAME_TEXT_SIZE] = {0};
  zone_version_t *first_wc_zone = NULL;
  char first_wc_apex[DNS_NAME_TEXT_SIZE] = {0};
  for (int depth = 0; depth < 16; depth++) {
    zone_db_entry_t *db_entry = *db_entry_ptr;
    zone_version_t *current_zone = *current_zone_ptr;
    if (!current_zone || !current_zone->image) {
      res[3] = (res[3] & 0xF0) | 0x02; // SERVFAIL
      *offset = initial_offset;
      *ancount = initial_ancount;
      *nscount = initial_nscount;
      *arcount = initial_arcount;
      return;
    }
    const zone_image_t *img = current_zone->image;
    const zone_image_name_t *img_names = zone_image_names(img);
    const zone_image_rr_t *img_rrs = zone_image_rrs(img);

    const zone_config_t *zcfg = (cfg && db_entry) ? zone_entry_config(cfg, db_entry) : NULL;
    zone_image_view_t cview;
    uint8_t zone_scope = 0;
    zone_client_view(img, cfg, zcfg, client_ip, ecs_trusted, ecs_addr, ecs_family, &cview, &zone_scope);
    time_t tinydns_now = cview.now;
    const char *client_loc = cview.loc;
    const char *client_loc_tag = cview.loc_tag;
    const char *client_ecs_tag = cview.ecs_tag;
    /* B8t-1: a zone cut over to by a CNAME whose SOA this client does not see is not served to it: the chain stops here
     * (the query's own zone was checked before, REFUSED) */
    if (depth > 0 && (img->flags & ZONE_IMAGE_F_SOA_ATTR) && zone_image_visible_soa(img, &cview, NULL) == ZONE_IMAGE_NONE)
      return;

    // ==== フェーズ1: 委任判定 ====
    additional_from_auth_t policy = (zcfg && zext(zcfg)->additional_from_auth_specified)
                                        ? zext(zcfg)->additional_from_auth
                                        : (cfg ? cfg->additional_from_auth : ADDITIONAL_AUTH_YES);
    bool is_ds_query = (num_qtypes > 0 && qtypes[0] == 43);
    if (find_delegation(img, current_qname, db_entry->domain, res,
                        max_res_len, offset, comp_ctx, nscount, arcount, is_ds_query, client_loc, client_ecs_tag, client_loc_tag, policy, &sib_ctx, dnssec_ok)) {
      return;
    }

    // ==== フェーズ2: QNAME完全一致検索 ====
    bool found = false, type_matched = false, cname_followed = false, wc_found = false;
    uint32_t qname_id = zone_image_find_name(img, current_qname);
    uint32_t q_first = 0, q_end = 0;
    if (qname_id != ZONE_IMAGE_NONE) {
      q_first = img_names[qname_id].first_rr;
      q_end = q_first + (img_names[qname_id].rr_count_flags & ZONE_IMAGE_NAME_COUNT_MASK);
    }
    /* B9a: this owner has an ALIAS RR and the zone has resolvers (alias-resolver): the ALIAS is expanded, not answered */
    uint64_t alias_key = 0;
    if (qname_id != ZONE_IMAGE_NONE && (img_names[qname_id].rr_count_flags & ZONE_IMAGE_NAME_ALIAS) && (qclass == 1 || qclass == 255))
      alias_key = alias_resolvers_key(cfg, zcfg, db_entry->source == ZONE_SRC_DB);
    uint16_t written_types[64];
    int written_count = 0;
    rr_filter_t flt = { client_loc, client_ecs_tag, client_loc_tag, zone_scope, answer_scope };
    bool has_any = (qtypes[0] == 255);
    bool skip_synthesis = false;
    if (has_any && minimal_any) {
      bool name_exists = false, has_cname = false, has_rrsig = false;
      for (uint32_t k = q_first; k < q_end; k++) {
        if (rr_not_served(img, k)) continue; // RFC 5155 §7.2.8 / LUA: 名前の存在に数えない
        uint32_t eff_ttl;
        note_ecs_variant(img, k, 255, zone_scope, answer_scope);
        if (!rr_valid(img, k, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &eff_ttl)) continue;
        name_exists = true;
        if (img_rrs[k].type == 5) has_cname = true;   // CNAME
        if (img_rrs[k].type == 46) has_rrsig = true;  // RRSIG
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
        char *hinfo_rd[2] = { "RFC8482", "" };
        hinfo_rec.rdata = hinfo_rd;
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
    for (uint32_t k = q_first; k < q_end; k++) {
      uint16_t r_class = img_rrs[k].class_val;
      bool class_matches = (qclass == 255 || qclass == r_class);
      if (!class_matches) continue;
      // RFC 5155 §7.2.8: NSEC3 チェーンのレコードは QTYPE NSEC3/RRSIG/ANY でも答えず、名前の存在にも数えない
      if (rr_not_served(img, k)) continue;
      uint32_t eff_ttl;
      note_ecs_variant(img, k, qtypes[0], zone_scope, answer_scope);
      if (!rr_valid(img, k, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &eff_ttl)) continue;
      found = true;
      uint16_t rec_type = img_rrs[k].type;
      bool follow_cname = false;
      if (rec_type == 5) {
        if (qtypes[0] != 5 && qtypes[0] != 255) { follow_cname = true; }
      }
      if (follow_cname) {
        if (image_serialize_rr(img, k, res, max_res_len, offset, comp_ctx, NULL, eff_ttl) < 0) {
          res[2] |= 0x02;
          return;
        } else
          (*ancount)++;
        if (dnssec_ok) {
          if (!attach_covering_rrsig(img, qname_id, NULL, 5, res, max_res_len, offset, comp_ctx, ancount)) {
            res[2] |= 0x02;
            return;
          }
        }
        char target[DNS_NAME_TEXT_SIZE];
        if (rr_target_text(img, k, target, sizeof(target))) {
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
          cname_followed = true;
        }
        break;
      } else {
        /* B9a: with an alias-resolver the ALIAS RR itself is no answer (PowerDNS with expand-alias=yes), and ANY gives the expanded A and AAAA only */
        if (alias_key && ((rec_type == DNS_TYPE_PDNS_ALIAS && r_class == 1) || (has_any && rec_type != 5))) continue;
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
          // R-04: DO=1 の ANY では RRSIG は各 RRset の後ろに付けるだけで、単独のRRとしては書かない
          if (has_any && dnssec_ok && rec_type == 46) continue;
          type_matched = true;
          // O-16: RRset はタイプごとに 1 回、全RRを続けて書き、その後ろに RRSIG
          if (rrset_type_seen(written_types, &written_count, rec_type)) continue;
          if (emit_rrset(img, qname_id, NULL, rec_type, qclass, &flt,
                         (sign_answers && rec_type != 46) ? RRSIG_REQUIRED : RRSIG_NONE, res, max_res_len, offset,
                         comp_ctx, ancount, &glue) < 0) {
            res[2] |= 0x02;
            return;
          }
        }
      }
    }

    // ==== B9a: ALIAS の展開 (A / AAAA / ANY) ====
    if (alias_key && found && !type_matched && !cname_followed && (qtypes[0] == 1 || qtypes[0] == 28 || has_any)) {
      int ok_types = 0;
      t_resolve_alias_expanded = true;
      int w = answer_alias(img, qname_id, alias_key, current_qname, qtypes[0], res, max_res_len, offset, comp_ctx, ancount, &ok_types);
      if (w < 0) {
        res[2] |= 0x02;
        return;
      }
      if (ok_types == 0) {                       // not resolved (yet), or the result is older than the stale limit
        t_resolve_alias_failed = true;
        res[3] = (res[3] & 0xF0) | 0x02;      // SERVFAIL
        *offset = initial_offset;
        *ancount = initial_ancount;
        *nscount = initial_nscount;
        *arcount = initial_arcount;
        return;
      }
      if (w > 0) type_matched = true;
    }

    // ==== フェーズ3: DNAME合成 ====
    if (!found) {
      bool dname_found = false;
      const char *dname_parent = current_qname;
      while ((img->flags & ZONE_IMAGE_F_DNAME) && (dname_parent = strchr_unescaped(dname_parent, '.')) != NULL) {
        dname_parent++;
        if (*dname_parent == '\0') break;
        uint32_t pid = zone_image_find_name(img, dname_parent);
        if (pid != ZONE_IMAGE_NONE) {
          uint32_t k = img_names[pid].first_rr;
          uint32_t pend = k + (img_names[pid].rr_count_flags & ZONE_IMAGE_NAME_COUNT_MASK);
          for (; k < pend; k++) {
            if (img_rrs[k].type == 39) {
              uint32_t eff_ttl;
              note_ecs_variant(img, k, 39, zone_scope, answer_scope);
              if (!rr_valid(img, k, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &eff_ttl)) continue;
              dname_found = true;
              char dname_target[DNS_NAME_TEXT_SIZE];
              if (!rr_target_text(img, k, dname_target, sizeof(dname_target))) break;

              // 先に DNAME RR自身を Answer セクションに追加
              if (image_serialize_rr(img, k, res, max_res_len, offset, comp_ctx, NULL, eff_ttl) < 0) {
                res[2] |= 0x02;
                return;
              }
              (*ancount)++;
              if (dnssec_ok) {
                if (!attach_covering_rrsig(img, pid, NULL, 39, res, max_res_len, offset, comp_ctx, ancount)) {
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
              int written = snprintf(synth_name + prefix_len, sizeof(synth_name) - prefix_len, "%s", dname_target);
              if (written < 0 || (size_t)written >= sizeof(synth_name) - prefix_len ||
                  write_uncompressed_name_ext(synth_wire, 0, sizeof(synth_wire), synth_name, false) < 0) {
                res[3] = (res[3] & 0xF0) | 6; // YXDOMAIN
                return;
              }

              // 255 バイト以内の場合は通常通り合成 CNAME を追加して追跡継続 (DNAME の TTL を写す)
              dns_record_t synth_cname;
              memset(&synth_cname, 0, sizeof(synth_cname));
              synth_cname.name = (char *)current_qname;
              synth_cname.type_code = 5;
              synth_cname.ttl_value = eff_ttl;
              char *synth_rd[1] = { synth_name };
              synth_cname.rdata = synth_rd;
              synth_cname.rdata_count = 1;
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
              cname_followed = true; found = true; break;
            }
          }
        }
        if (dname_found) break;
      }

      // ==== フェーズ4: ワイルドカード合成 ====
      // RFC 4592 2.2.1 / RFC 4035 3.1.3.3 / RFC 5155 B.2.1: a name that exists only as an Empty Non-Terminal
      // (it has descendants) still EXISTS, so a wildcard must not synthesize an answer for it (NODATA instead).
      // A zone with no wildcard owner has nothing to find: skip the walk up the name (ZONE_IMAGE_F_WILDCARD).
      if (!dname_found && (img->flags & ZONE_IMAGE_F_WILDCARD) &&
          !name_exists_in_zone(img, current_qname, client_loc, client_ecs_tag, client_loc_tag)) {
        const char *parent = current_qname;
        char wc_name[DNS_NAME_TEXT_SIZE];
        wc_name[0] = '*';
        wc_name[1] = '.';
        while ((parent = strchr_unescaped(parent, '.')) != NULL) {
          parent++;
          if (*parent == '\0') break;
          size_t parent_len = current_qname_len - (size_t)(parent - current_qname);
          if (parent_len + 3 > sizeof(wc_name)) break;
          wc_found = false;
          memcpy(&wc_name[2], parent, parent_len + 1);
          uint32_t wc_id = zone_image_find_name(img, wc_name);
          if (wc_id != ZONE_IMAGE_NONE) {
            uint16_t wc_written_types[64];
            int wc_written_count = 0;
            uint32_t k = img_names[wc_id].first_rr;
            uint32_t wend = k + (img_names[wc_id].rr_count_flags & ZONE_IMAGE_NAME_COUNT_MASK);
            for (; k < wend; k++) {
              uint16_t r_class = img_rrs[k].class_val;
              bool class_matches = (qclass == 255 || qclass == r_class);
              if (!class_matches) continue;
              if (rr_not_served(img, k)) continue; // LUA (B9a): a wildcard that holds only LUA records is not there
              uint32_t eff_ttl;
              note_ecs_variant(img, k, qtypes[0], zone_scope, answer_scope);
              if (!rr_valid(img, k, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &eff_ttl)) continue;
              found = true;
              wc_found = true;
              t_query_rrl_info.wildcard = true; /* D-05: RRL は "*.<ゾーン>" で数える */
              uint16_t rec_type = img_rrs[k].type;
              bool follow_cname = false;
              if (rec_type == 5) {
                if (qtypes[0] != 5 && qtypes[0] != 255) { follow_cname = true; }
              }
              if (follow_cname) {
                if (!any_cname_wc_expanded) {
                  any_cname_wc_expanded = true;
                  strncpy(first_wc_qname, current_qname, sizeof(first_wc_qname) - 1);
                  first_wc_qname[sizeof(first_wc_qname) - 1] = '\0';
                  first_wc_zone = current_zone;
                  strncpy(first_wc_apex, db_entry->domain, sizeof(first_wc_apex) - 1);
                  first_wc_apex[sizeof(first_wc_apex) - 1] = '\0';
                }
                if (image_serialize_rr(img, k, res, max_res_len, offset, comp_ctx, current_qname, eff_ttl) < 0) {
                  res[2] |= 0x02;
                  return;
                } else
                  (*ancount)++;
                if (dnssec_ok) {
                  if (!attach_covering_rrsig(img, wc_id, current_qname, 5, res, max_res_len, offset, comp_ctx, ancount)) {
                    res[2] |= 0x02;
                    return;
                  }
                }
                char target[DNS_NAME_TEXT_SIZE];
                if (rr_target_text(img, k, target, sizeof(target))) {
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
                  cname_followed = true;
                }
                break;
              } else {
                if (qtypes[0] == 255 || qtypes[0] == rec_type) {
                  // R-04 / O-16: exact-name の場合と同じ (RRSIG は各 RRset の後ろ、RRset ごとに 1 回)
                  if (has_any && dnssec_ok && rec_type == 46) continue;
                  type_matched = true;
                  if (rrset_type_seen(wc_written_types, &wc_written_count, rec_type)) continue;
                  if (emit_rrset(img, wc_id, current_qname, rec_type, qclass, &flt,
                                 (sign_answers && rec_type != 46) ? RRSIG_REQUIRED : RRSIG_NONE, res, max_res_len,
                                 offset, comp_ctx, ancount, &glue) < 0) {
                    res[2] |= 0x02;
                    return;
                  }
                }
              }
            }
          }
          if (wc_found)
            break;

          // ★重要: RFC 4592 準拠 (親存在チェック)
          if (name_exists_in_zone(img, parent, client_loc, client_ecs_tag, client_loc_tag))
            break;
        }
      }
    }

    // ==== フェーズ5: CNAMEチェーン処理・クロスゾーン切り替え ====
    if (cname_followed) {
      /* X-27, RFC 1034 §4.3.2 step 3a: CNAME/DNAME の後は新しい QNAME で step 1 からやり直す。step 2 で
       * 「QNAME に最も近い祖先のゾーン」を選ぶので、対象が今のゾーンの下でも、同じビューに子ゾーンが
       * あればそちらで答える (以前は親ゾーンに留まり、子への委任を返していた)。DS は R-32 の規則で
       * find_zone_for_query() が親ゾーンを選ぶ。forward/program ゾーンのデータは持たないので CNAME で止める。 */
      zone_db_entry_t *new_db_entry = find_zone_for_query(view, current_qname, qtypes[0]);
      if (!view && domain_name_is_at_or_below(current_qname, db_entry->domain) &&
          !(qtypes[0] == 43 && domain_names_match_ci(current_qname, db_entry->domain)))
        new_db_entry = db_entry; // ビューの無い呼び出し (応答キャッシュの構築など) はこのゾーンだけで続ける
      if (!new_db_entry || new_db_entry->kind == ZONE_KIND_FORWARD || new_db_entry->kind == ZONE_KIND_PROGRAM)
        return;
      if (new_db_entry != db_entry) {
        /* allow-query of the zone the CNAME leads into: a client that may not ask that zone gets the chain up to here (BIND stops
         * the same way: the partial answer is returned).  Never stored in the response cache (it depends on the client). */
        if (cfg && cfg->acl_query_active && view &&
            !zone_query_permitted(cfg, zone_entry_config(cfg, new_db_entry), view->name, client_ip)) {
          t_resolve_crossed_zone = true;
          return;
        }
        *db_entry_ptr = new_db_entry;
        *current_zone_ptr = atomic_load_explicit(&new_db_entry->rcu.active, memory_order_acquire);
        t_resolve_crossed_zone = true;
      }
      continue;
    }

    // ==== フェーズ6: 複数QTYPE追加解決 ====
    bool all_matched = type_matched;
    uint32_t included_mask = 0;
    if (found && num_qtypes > 1) {
      uint32_t final_id = zone_image_find_name(img, current_qname);
      for (int j = 1; j < num_qtypes; j++) {
        uint16_t qtx = qtypes[j];
        bool this_qtx_failed = false;
        bool qtx_matched = false;
        int saved_glue_count = glue.count;
        resolve_checkpoint_t cp = save_checkpoint(offset, ancount, nscount, arcount);
        int qtx_mode = (sign_answers && qtx != 46) ? RRSIG_REQUIRED : RRSIG_NONE;

        // O-16: RRset を続けて書き、その後ろに RRSIG (exact-name と同じヘルパー)
        int w = (alias_key && qtx == DNS_TYPE_PDNS_ALIAS)   /* B9a: with an alias-resolver the ALIAS RR is not an answer (as for the first QTYPE) */
                    ? 0
                    : emit_rrset(img, final_id, NULL, qtx, qclass, &flt, qtx_mode, res,
                                 max_res_len, offset, comp_ctx, ancount, &glue);
        if (w < 0) this_qtx_failed = true;
        else if (w > 0) qtx_matched = true;

        /* B9a: the extra QTYPEs A / AAAA of an RFC 10029 query at an ALIAS name are expanded like the first one (a type without a usable
         * result is simply not matched here: only the first QTYPE decides SERVFAIL) */
        if (!qtx_matched && !this_qtx_failed && alias_key && (qtx == 1 || qtx == 28) && final_id == qname_id) {
          int ok_x = 0;
          t_resolve_alias_expanded = true;
          int wa = answer_alias(img, final_id, alias_key, current_qname, qtx, res, max_res_len, offset, comp_ctx, ancount, &ok_x);
          if (wa < 0) this_qtx_failed = true;
          else if (wa > 0) qtx_matched = true;
        }

        if (!qtx_matched && !this_qtx_failed && (img->flags & ZONE_IMAGE_F_WILDCARD)) {
          const char *parent = current_qname;
          char wc_name[DNS_NAME_TEXT_SIZE];
          wc_name[0] = '*'; wc_name[1] = '.';
          while ((parent = strchr_unescaped(parent, '.')) != NULL) {
            parent++; if (*parent == '\0') break;
            size_t parent_len = current_qname_len - (size_t)(parent - current_qname);
            if (parent_len + 3 > sizeof(wc_name)) break;
            wc_found = false;
            memcpy(&wc_name[2], parent, parent_len + 1);
            uint32_t wc_id = zone_image_find_name(img, wc_name);
            if (wc_id != ZONE_IMAGE_NONE) {
              int ww = emit_rrset(img, wc_id, current_qname, qtx, qclass, &flt, qtx_mode,
                                  res, max_res_len, offset, comp_ctx, ancount, &glue);
              if (ww < 0) this_qtx_failed = true;
              else if (ww > 0) wc_found = qtx_matched = true;
              if (wc_found) t_query_rrl_info.wildcard = true; /* D-05 */
            }
            if (wc_found || this_qtx_failed) break;

            // ★重要: RFC 4592 準拠 (親存在チェック)
            if (name_exists_in_zone(img, parent, client_loc, client_ecs_tag, client_loc_tag))
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
        name_exists_in_zone(img, current_qname, client_loc, client_ecs_tag, client_loc_tag)) {
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
      uint32_t apex_id = zone_image_find_name(img, db_entry->domain);
      if (apex_id != ZONE_IMAGE_NONE) {
        uint32_t k = img_names[apex_id].first_rr;
        uint32_t aend = k + (img_names[apex_id].rr_count_flags & ZONE_IMAGE_NAME_COUNT_MASK);
        for (; k < aend; k++) {
          if (img_rrs[k].type != 6) continue;
          uint32_t eff_ttl;
          if (!rr_valid(img, k, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &eff_ttl)) continue;
          uint32_t minimum_ttl = 3600;
          (void)zone_image_soa_minimum(img, k, &minimum_ttl);
          if (image_serialize_rr(img, k, res, max_res_len, offset, comp_ctx, NULL,
                                 ttl_with_override(eff_ttl, minimum_ttl)) < 0) {
            res[2] |= 0x02;
            return;
          } else
            (*nscount)++;
          if (dnssec_ok) {
            // RFC 2181 §5.2 / RFC 4035 §3.1.5: RRSIG TTL must match covered SOA minimum_ttl
            if (!attach_covering_rrsig_ext(img, apex_id, NULL, 6, res, max_res_len, offset, comp_ctx, nscount,
                                           minimum_ttl)) {
              res[2] |= 0x02;
              return;
            }
          }
          break;
        }
      }
    }

    // ==== フェーズ8: NSEC付加 ====
    resolve_checkpoint_t nsec_cp = save_checkpoint(offset, ancount, nscount, arcount);
    bool nsec_failed = false;
    const zone_image_rr_t *nsec_attached[8];
    int nsec_attached_cnt = 0;
    const zone_image_rr_t *attached_nsec3[8];
    int attached_nsec3_cnt = 0;
    zone_n3_t n3;
    bool has_n3 = dnssec_ok && zone_nsec3(img, db_entry->domain, &n3);
    if (dnssec_ok && !has_n3) {
      /* O-17: attach_denial_record() は同じ NSEC を 2 回書かず、RRSIG が入らないときも失敗を返す */
      if (found && wc_found) {
        // RFC 4035 §3.1.3.3: Wildcard answer proof (QNAME non-existence)
        uint32_t cover = find_covering_nsec(img, current_qname);
        if (!attach_denial_record(img, cover, 0xFFFFFFFF, res, max_res_len, offset, comp_ctx, nscount,
                                  nsec_attached, &nsec_attached_cnt))
          nsec_failed = true;
        if (!all_matched && !nsec_failed) {
          // RFC 4035 §3.1.3.4: wildcard NODATA: the NSEC of the wildcard owner proves the type is missing
          const char *encloser = find_closest_encloser(img, current_qname, db_entry->domain, client_loc, client_ecs_tag, client_loc_tag);
          if (encloser) {
            char wc_name[DNS_NAME_TEXT_SIZE];
            snprintf(wc_name, sizeof(wc_name), "*.%s", encloser);
            uint32_t wc_id = zone_image_find_name(img, wc_name);
            if (wc_id != ZONE_IMAGE_NONE) {
              uint32_t rk = zone_image_rrset_next(img, wc_id, 47, zone_image_name_first_rr(img, wc_id));
              if (rk != ZONE_IMAGE_NONE) {
                if (!attach_denial_record(img, rk, 0xFFFFFFFF, res, max_res_len, offset, comp_ctx,
                                          nscount, nsec_attached, &nsec_attached_cnt))
                  nsec_failed = true;
              }
            }
          }
        }
      } else if (found && !all_matched) {
        bool nsec_at_name = false;
        uint32_t nid = zone_image_find_name(img, current_qname);
        if (nid != ZONE_IMAGE_NONE) {
          uint32_t k = img_names[nid].first_rr;
          uint32_t nend = k + (img_names[nid].rr_count_flags & ZONE_IMAGE_NAME_COUNT_MASK);
          for (; k < nend; k++) {
            if (img_rrs[k].type == 47 /* NSEC */) {
              if (img_rrs[k].rdata_len < 1) break; // 壊れたNSECは無視
              uint32_t eff_ttl;
              if (!rr_valid(img, k, tinydns_now, client_loc, client_ecs_tag, client_loc_tag, &eff_ttl)) continue;
              nsec_at_name = true;
              if (!attach_denial_record(img, k, eff_ttl, res, max_res_len, offset, comp_ctx, nscount,
                                        nsec_attached, &nsec_attached_cnt))
                nsec_failed = true;
              break;
            }
          }
        }
        if (ent_nodata && !nsec_failed && !nsec_at_name) {
          // An ENT owns no NSEC; the NSEC that covers it (its next name is a descendant) proves it exists.
          uint32_t cover = find_covering_nsec(img, current_qname);
          if (!attach_denial_record(img, cover, 0xFFFFFFFF, res, max_res_len, offset, comp_ctx, nscount,
                                    nsec_attached, &nsec_attached_cnt))
            nsec_failed = true;
        }
      } else if (!found) {
        uint32_t cover = find_covering_nsec(img, current_qname);
        if (!attach_denial_record(img, cover, 0xFFFFFFFF, res, max_res_len, offset, comp_ctx, nscount,
                                  nsec_attached, &nsec_attached_cnt))
          nsec_failed = true;

        if (!nsec_failed) {
          const char *encloser = find_closest_encloser(img, current_qname, db_entry->domain, client_loc, client_ecs_tag, client_loc_tag);
          if (encloser) {
            char wc_name[DNS_NAME_TEXT_SIZE];
            int written = snprintf(wc_name, sizeof(wc_name), "*.%s", encloser);
            if (written > 0 && (size_t)written < sizeof(wc_name)) {
              if (cover == ZONE_IMAGE_NONE || !nsec_covers_name(img, cover, wc_name)) {
                uint32_t wc_cover = find_covering_nsec(img, wc_name);
                if (!attach_denial_record(img, wc_cover, 0xFFFFFFFF, res, max_res_len, offset, comp_ctx,
                                          nscount, nsec_attached, &nsec_attached_cnt))
                  nsec_failed = true;
              }
            }
          }
        }
      }
    } else if (has_n3) {
      {
        uint8_t algo = n3.algorithm;
        uint16_t iterations = n3.iterations;
        const uint8_t *salt = n3.salt;
        size_t salt_len = n3.salt_len;

        if (found && wc_found) {
          // RFC 5155 §7.2.5 & §8.5: Wildcard answer proof (Closest Encloser & Next Closer covering)
          const char *encloser = find_closest_encloser(img, current_qname, db_entry->domain, client_loc, client_ecs_tag, client_loc_tag);
          if (!encloser) encloser = db_entry->domain;
          char ce_hash[64];
          if (compute_nsec3_hash(encloser, algo, iterations, salt, salt_len, ce_hash, sizeof(ce_hash))) {
            uint32_t ce_rec = find_matching_nsec3(img, n3.chain, ce_hash, db_entry->domain);
            if (ce_rec != ZONE_IMAGE_NONE) {
              if (!attach_nsec3_record(img, ce_rec, res, max_res_len, offset, comp_ctx, nscount, attached_nsec3, &attached_nsec3_cnt)) {
                nsec_failed = true;
              }
            }
          }

          char nc_name[DNS_NAME_TEXT_SIZE];
          if (!nsec_failed && find_next_closer_name(current_qname, encloser, nc_name, sizeof(nc_name))) {
            char nc_hash[64];
            if (compute_nsec3_hash(nc_name, algo, iterations, salt, salt_len, nc_hash, sizeof(nc_hash))) {
              uint32_t nc_cover = find_covering_nsec3(img, n3.chain, nc_hash);
              if (nc_cover != ZONE_IMAGE_NONE) {
                if (!attach_nsec3_record(img, nc_cover, res, max_res_len, offset, comp_ctx, nscount, attached_nsec3, &attached_nsec3_cnt)) {
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
              uint32_t wc_rec = find_matching_nsec3(img, n3.chain, wc_hash, db_entry->domain);
              if (wc_rec != ZONE_IMAGE_NONE) {
                if (!attach_nsec3_record(img, wc_rec, res, max_res_len, offset, comp_ctx, nscount, attached_nsec3, &attached_nsec3_cnt)) {
                  nsec_failed = true;
                }
              }
            }
          }
        } else if (found && !all_matched) {
          // NODATA: matching NSEC3 for current_qname
          char q_hash[64];
          if (compute_nsec3_hash(current_qname, algo, iterations, salt, salt_len, q_hash, sizeof(q_hash))) {
            uint32_t m_rec = find_matching_nsec3(img, n3.chain, q_hash, db_entry->domain);
            if (m_rec != ZONE_IMAGE_NONE) {
              if (!attach_nsec3_record(img, m_rec, res, max_res_len, offset, comp_ctx, nscount, attached_nsec3, &attached_nsec3_cnt)) {
                nsec_failed = true;
              }
            }
          }
        } else if (!found) {
          // NXDOMAIN: Closest Encloser, Next Closer, Wildcard
          const char *encloser = find_closest_encloser(img, current_qname, db_entry->domain, client_loc, client_ecs_tag, client_loc_tag);
          if (!encloser) encloser = db_entry->domain;
          char ce_hash[64];
          if (compute_nsec3_hash(encloser, algo, iterations, salt, salt_len, ce_hash, sizeof(ce_hash))) {
            uint32_t ce_rec = find_matching_nsec3(img, n3.chain, ce_hash, db_entry->domain);
            if (ce_rec != ZONE_IMAGE_NONE) {
              if (!attach_nsec3_record(img, ce_rec, res, max_res_len, offset, comp_ctx, nscount, attached_nsec3, &attached_nsec3_cnt)) {
                nsec_failed = true;
              }
            }
          }

          char nc_name[DNS_NAME_TEXT_SIZE];
          if (!nsec_failed && find_next_closer_name(current_qname, encloser, nc_name, sizeof(nc_name))) {
            char nc_hash[64];
            if (compute_nsec3_hash(nc_name, algo, iterations, salt, salt_len, nc_hash, sizeof(nc_hash))) {
              uint32_t nc_cover = find_covering_nsec3(img, n3.chain, nc_hash);
              if (nc_cover != ZONE_IMAGE_NONE) {
                if (!attach_nsec3_record(img, nc_cover, res, max_res_len, offset, comp_ctx, nscount, attached_nsec3, &attached_nsec3_cnt)) {
                  nsec_failed = true;
                }
              }
            }
          }

          char wc_name[DNS_NAME_TEXT_SIZE];
          snprintf(wc_name, sizeof(wc_name), "*.%s", encloser);
          char wc_hash[64];
          if (!nsec_failed && compute_nsec3_hash(wc_name, algo, iterations, salt, salt_len, wc_hash, sizeof(wc_hash))) {
            uint32_t wc_cover = find_covering_nsec3(img, n3.chain, wc_hash);
            if (wc_cover != ZONE_IMAGE_NONE) {
              if (!attach_nsec3_record(img, wc_cover, res, max_res_len, offset, comp_ctx, nscount, attached_nsec3, &attached_nsec3_cnt)) {
                nsec_failed = true;
              }
            }
          }
        }
      }
    }

    if (dnssec_ok && any_cname_wc_expanded && !nsec_failed) {
      zone_version_t *wc_zone = first_wc_zone ? first_wc_zone : current_zone;
      const zone_image_t *wc_img = wc_zone->image;
      const char *wc_apex = first_wc_apex[0] ? first_wc_apex : db_entry->domain;
      zone_n3_t wc_n3;
      if (!zone_nsec3(wc_img, wc_apex, &wc_n3)) {
        uint32_t cover = find_covering_nsec(wc_img, first_wc_qname);
        if (!attach_denial_record(wc_img, cover, 0xFFFFFFFF, res, max_res_len, offset, comp_ctx, nscount,
                                  nsec_attached, &nsec_attached_cnt))
          nsec_failed = true;
      } else {
        {
          uint8_t algo = wc_n3.algorithm;
          uint16_t iterations = wc_n3.iterations;
          const uint8_t *salt = wc_n3.salt;
          size_t salt_len = wc_n3.salt_len;

          const char *encloser = find_closest_encloser(wc_img, first_wc_qname, wc_apex, client_loc, client_ecs_tag, client_loc_tag);
          if (!encloser) encloser = wc_apex;
          char ce_hash[64];
          if (compute_nsec3_hash(encloser, algo, iterations, salt, salt_len, ce_hash, sizeof(ce_hash))) {
            uint32_t ce_rec = find_matching_nsec3(wc_img, wc_n3.chain, ce_hash, wc_apex);
            if (ce_rec != ZONE_IMAGE_NONE) {
              if (!attach_nsec3_record(wc_img, ce_rec, res, max_res_len, offset, comp_ctx, nscount, attached_nsec3, &attached_nsec3_cnt)) {
                nsec_failed = true;
              }
            }
          }

          char nc_name[DNS_NAME_TEXT_SIZE];
          if (!nsec_failed && find_next_closer_name(first_wc_qname, encloser, nc_name, sizeof(nc_name))) {
            char nc_hash[64];
            if (compute_nsec3_hash(nc_name, algo, iterations, salt, salt_len, nc_hash, sizeof(nc_hash))) {
              uint32_t nc_cover = find_covering_nsec3(wc_img, wc_n3.chain, nc_hash);
              if (nc_cover != ZONE_IMAGE_NONE) {
                if (!attach_nsec3_record(wc_img, nc_cover, res, max_res_len, offset, comp_ctx, nscount, attached_nsec3, &attached_nsec3_cnt)) {
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
    if (type_matched && minimal_mode == MINIMAL_NO && needs_ns) {
      /* R-03: 頂点の NS は署名された RRset。DO=1 なら RRSIG(NS) も付け、入りきらなければ TC (RFC 4035 §3.1.1) */
      /* Authority section: without ECS (RFC 7871 §7.3.1), as find_delegation() */
      rr_filter_t ns_flt = { client_loc, NULL, client_loc_tag, 0, NULL };
      if (emit_rrset(img, zone_image_find_name(img, db_entry->domain), NULL, 2, 255, &ns_flt,
                     dnssec_ok ? RRSIG_REQUIRED : RRSIG_NONE, res, max_res_len, offset, comp_ctx, nscount,
                     &glue) < 0) {
        res[2] |= 0x02;
        return;
      }
    }

    // ==== フェーズ10: Additional Glue付加 ====
    if (minimal_mode != MINIMAL_YES && glue.count > 0 && policy != ADDITIONAL_AUTH_NO) {
      for (int k = 0; k < glue.count; k++) {
        if (!append_glue_records(img, glue.targets[k], db_entry->domain,
                                 res, max_res_len, offset, comp_ctx, arcount,
                                 client_loc, client_loc_tag, policy, &sib_ctx, dnssec_ok)) {
          t_resolve_additional_cut = true; // 応答キャッシュに入れない (大きいバッファの問い合わせにも返ってしまう)
          /* バッファ上限に達した場合は以後のグルー追加を中断 (RFC 2181 §9: TC は立てない)。委任の応答 (find_delegation()) も、
           * 入りきらない兄弟のグルーでは TC を立てず、以後の兄弟のグルーを足さない (RFC 9471 §3.2。A1)。 */
          break;
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
                         zone_version_t **current_zone_ptr, uint8_t *res,
                         size_t max_res_len, uint16_t *offset,
                         compress_ctx_t *comp_ctx, uint16_t *ancount,
                         uint16_t *nscount, uint16_t *arcount,
                         int minimal_mode,
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
                      max_res_len, offset, comp_ctx, ancount, nscount, arcount, minimal_mode,
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
  const zone_ext_t *x = zext(z);
  size_t pos = 0;
  pos += (size_t)snprintf(out + pos, out_cap - pos, "path=%s|user=%s|timeout=%u|maxfail=%u|disable_tc=%d|args=",
                          x->program_path ? x->program_path : "",
                          x->program_user ? x->program_user : "",
                          x->program_timeout_ms, x->program_max_failures,
                          x->disable_auto_tc_flag ? 1 : 0);
  for (int i = 0; i < x->program_args_count && pos < out_cap; i++) {
    pos += (size_t)snprintf(out + pos, out_cap - pos, "%s;", x->program_args[i]);
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
#ifdef __FreeBSD__
        /* X-11: ここはサンドボックスの中。kill(pid) は ECAPMODE (PROC_TRAPCAP で SIGTRAP) になり
         * バックエンドごと止まるので、起動時に得たプロセス記述子で止める。close() で回収される。 */
        if (plugin->proc_fd >= 0) {
          pdkill(plugin->proc_fd, SIGKILL);
          close(plugin->proc_fd);
          plugin->proc_fd = -1;
        }
#else
        kill(plugin->pid, SIGKILL);
        waitpid(plugin->pid, NULL, WNOHANG);
#endif
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

/* 2 バイトの長さとメッセージを1回の writev() で書く (RFC 7766 §8)。書き切れなければ
 * timeout_ms まで書き込み可能を待って続ける。戻り値はメッセージ長、失敗時 -1。 */
static ssize_t write_dns_tcp_timeout(int fd, const uint8_t *msg, size_t len, uint32_t timeout_ms) {
  int64_t deadline = monotonic_ms() + timeout_ms;
  uint8_t prefix[2] = { (uint8_t)(len >> 8), (uint8_t)(len & 0xFF) };
  struct iovec iov[2] = { { .iov_base = prefix, .iov_len = 2 },
                          { .iov_base = (void *)(uintptr_t)msg, .iov_len = len } };
  struct iovec *cur = iov;
  int cnt = 2;
  while (cnt > 0) {
    uint32_t rem = remaining_ms(deadline);
    if (rem == 0) return -1;
    struct pollfd pfd = { .fd = fd, .events = POLLOUT, .revents = 0 };
    int ret = poll(&pfd, 1, (int)rem);
    if (ret < 0 && errno == EINTR) continue;
    if (ret <= 0 || (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) return -1;
    ssize_t n = writev(fd, cur, cnt);
    if (n <= 0) {
      if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
      return -1;
    }
    while (cnt > 0 && (size_t)n >= cur->iov_len) {
      n -= (ssize_t)cur->iov_len;
      cur++;
      cnt--;
    }
    if (cnt > 0) {
      cur->iov_base = (uint8_t *)cur->iov_base + n;
      cur->iov_len -= (size_t)n;
    }
  }
  return (ssize_t)len;
}

STATIC_TEST ssize_t forward_via_tcp(const struct sockaddr_storage *ss, size_t ss_len,
                               const uint8_t *query, size_t query_len,
                               uint8_t *resp_out, size_t resp_out_cap,
                               uint32_t timeout_ms) {
  if (!ss || !query || !resp_out) return -1;
  /* D-20: 接続の完了待ちも同じ締切に含める (以前はブローカーの固定 4 秒) */
  tcp_sockopts_t copts = { .connect_timeout_ms = timeout_ms > 0 ? (int)timeout_ms : 1 };
  int64_t deadline = monotonic_ms() + timeout_ms;
  int fd = broker_connect_opts(ss->ss_family, SOCK_STREAM, (struct sockaddr *)ss, ss_len, &copts);
  if (fd < 0) return -1;
  timeout_ms = remaining_ms(deadline);

  if (query_len > 65535 || write_dns_tcp_timeout(fd, query, query_len, timeout_ms) != (ssize_t)query_len) {
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

_Thread_local query_rrl_info_t t_query_rrl_info;
/* D1a: process_dns_not_ready_routed() is asked whether the query may be parked (see there) */
static _Thread_local bool t_nr_probe;
/* X-20: 直前の要求の TSIG の状態 (鍵は設定スナップショット内)。RRL の slip 応答の署名に使う */
static _Thread_local tsig_request_t t_query_tsig;

size_t dns_rrl_slip_response(uint8_t *res, size_t res_len, size_t buf_cap) {
  if (res_len < DNS_HEADER_SIZE) return res_len;
  res[2] |= 0x02; // TC=1
  /* 質問の終わりは応答自身から求める (要求の質問を写していない応答 (QDCOUNT=0 の FORMERR など) でも
   * OPT の途中で切らない)。質問セクションまで切り詰めるが、OPT は残す (RFC 6891 §7) */
  size_t q_end = get_question_end_offset(res, res_len, (uint16_t)((res[4] << 8) | res[5]));
  size_t len = dns_truncate_keep_opt(res, res_len, q_end);
  if (t_query_tsig.status == TSIG_REQ_NONE || t_query_tsig.status == TSIG_REQ_FORMERR) return len;
  size_t limit = t_query_tsig.res_limit;
  if (limit == 0 || limit > buf_cap) limit = buf_cap;
  int signed_len = tsig_finish_response(res, len, limit, &t_query_tsig);
  if (signed_len >= DNS_HEADER_SIZE) return (size_t)signed_len;
  /* HMAC の計算に失敗したときだけ。以前と同じ無署名の TC 応答 (クライアントは TCP で問い直す) */
  syslog(LOG_WARNING, "[RRL] could not sign the slip response; sending it unsigned");
  return len;
}

_Thread_local static uint8_t s_forward_req_buf[65535];
_Thread_local static uint8_t s_forward_res_buf[65535];

STATIC_TEST int dispatch_forward_zone(const zone_config_t *zcfg, const uint8_t *req, size_t req_len,
                                 uint8_t *res, size_t max_res_len) {
  const zone_ext_t *x = zext(zcfg);
  if (req_len < DNS_HEADER_SIZE || x->forwarders_count == 0) {
    return build_synthetic_servfail(req, req_len, res, max_res_len);
  }
  if (req_len > sizeof(s_forward_req_buf)) {
    return build_synthetic_servfail(req, req_len, res, max_res_len);
  }

  // H-3: 1クエリ全体で共有する絶対締切。以降の全I/O呼び出しは
  // 各フォワーダーにフル分与せず、この締切までの残り時間を使う。
  uint32_t total_budget = x->forward_timeout_ms > 0 ? x->forward_timeout_ms : 2000;
  int64_t deadline = monotonic_ms() + total_budget;

  memcpy(s_forward_req_buf, req, req_len);
  uint16_t fresh_id = (uint16_t)(arc4random() & 0xFFFF);
  s_forward_req_buf[0] = fresh_id >> 8;
  s_forward_req_buf[1] = fresh_id & 0xFF;

  for (int i = 0; i < x->forwarders_count; i++) {
    uint32_t rem = remaining_ms(deadline);
    if (rem == 0) {
      syslog(LOG_WARNING, "[Forward] zone '%s': total timeout budget (%ums) expired; stopping forwarder loop",
             zcfg->domain, total_budget);
      break;
    }

    ip_port_t *fwd = &x->forwarders[i];
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

    /* D-20: 残り時間を、まだ試していないフォワーダー (このフォワーダーを含む) で等分する。
     * 最初のフォワーダーが応答しなくても、後ろのフォワーダーに時間が残る。 */
    uint32_t share = rem / (uint32_t)(x->forwarders_count - i);
    if (share == 0) share = 1;
    int64_t fwd_deadline = monotonic_ms() + share;

    ssize_t got = -1;
    bool mismatched = false;
    if (send(sock, s_forward_req_buf, req_len, 0) == (ssize_t)req_len) {
      /* ID・QR・質問が一致する応答だけを受け取る (RFC 5452 §9.1)。一致しないデータグラムは
       * 捨てて、このフォワーダーの持ち時間が尽きるまで待ち続ける (D-20)。 */
      for (;;) {
        uint32_t wait_ms = remaining_ms(fwd_deadline);
        if (wait_ms == 0) break;
        struct pollfd pfd = { .fd = sock, .events = POLLIN };
        int pr = poll(&pfd, 1, (int)wait_ms);
        if (pr < 0 && errno == EINTR) continue;
        if (pr <= 0) break;
        ssize_t n = recv(sock, s_forward_res_buf, sizeof(s_forward_res_buf), 0);
        if (n < 0) break; /* ICMP unreachable など: 次のフォワーダーへ */
        if (n >= (ssize_t)DNS_HEADER_SIZE &&
            ((s_forward_res_buf[0] << 8) | s_forward_res_buf[1]) == fresh_id &&
            (s_forward_res_buf[2] & 0x80) &&
            question_section_matches(s_forward_res_buf, (size_t)n, req, req_len)) {
          got = n;
          break;
        }
        mismatched = true;
      }
    }
    close(sock);

    if (mismatched)
      syslog(LOG_WARNING, "[Forward] zone '%s': forwarder '%s:%d' returned a mismatched "
             "response (id/question mismatch), discarded", zcfg->domain, fwd->ip, fwd->port);
    if (got < (ssize_t)DNS_HEADER_SIZE) {
      syslog(LOG_WARNING, "[Forward] zone '%s': forwarder '%s:%d' timed out or failed, trying next",
             zcfg->domain, fwd->ip, fwd->port);
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

  syslog(LOG_ERR, "[Forward] zone '%s': all %d forwarder(s) failed or timed out", zcfg->domain, x->forwarders_count);
  return build_synthetic_servfail(req, req_len, res, max_res_len);
}

bool spawn_one_program_plugin(zone_config_t *zcfg, const char *view_name, program_plugin_t *out) {
  const zone_ext_t *x = zext(zcfg);
  if (!x->program_path) {
    syslog(LOG_ERR, "[Plugin] zone '%s' program_path is NULL; refusing to spawn", zcfg->domain);
    return false;
  }

  /* program-user は fork 前に解決する (O-18: fork した子で getpwnam() を呼ばない) */
  uid_t prog_uid = (uid_t)-1;
  gid_t prog_gid = (gid_t)-1;
  bool prog_user_found = x->program_user && lookup_user_ids(x->program_user, &prog_uid, &prog_gid);
  /* P4: a program-user that is root by another name (uid 0, or the root group as its primary group) is refused, like no
   * program-user as root below (validate_program_zone_users() refuses the configuration first; this is the fail-closed spawn) */
  if (prog_user_found && (prog_uid == 0 || prog_gid == 0)) {   /* the ids resolved above: no second name lookup here */
    syslog(LOG_ERR, "[Plugin] zone '%s': program-user '%s' is uid %u, gid %u; refusing to run the plugin as root or in the root group",
           zcfg->domain, x->program_user, (unsigned)prog_uid, (unsigned)prog_gid);
    return false;
  }
  /* S-1: the plugin gets an empty environment (as the database loader does, dns_db_supervisor.c): nothing of the
   * server's environment (paths, debugging variables, anything an operator exported) reaches a zone's program.  TZ is
   * kept so that its time stamps match the server's.  Read before the fork (no getenv() in the child). */
  const char *tz = getenv("TZ");
  char tzenv[136] = "";
  char *plugin_envp[2] = { NULL, NULL };
  if (tz) {
    snprintf(tzenv, sizeof(tzenv), "TZ=%s", tz);
    plugin_envp[0] = tzenv;
  }

  int in_pipe[2];  // parent(karidns) write -> child(script) stdin
  int out_pipe[2]; // child(script) stdout -> parent(karidns) read
  if (pipe(in_pipe) != 0 || pipe(out_pipe) != 0) {
    syslog(LOG_ERR, "[Plugin] pipe() failed for zone '%s': %m", zcfg->domain);
    return false;
  }

  int proc_fd = -1;
#ifdef __FreeBSD__
  /* X-11: 子を止めるのはサンドボックスに入った後なので、pid ではなくプロセス記述子で持つ */
  pid_t pid = pdfork(&proc_fd, PD_CLOEXEC);
#else
  pid_t pid = fork();
#endif
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
    if (!x->program_user && geteuid() == 0) {
      // 標準エラーはまだ生きている(closefromはSTDERR_FILENO+1から)ので出力可能
      fprintf(stderr, "[FATAL] Zone '%s': 'program-user' is not set and karidns is running "
              "as root; refusing to exec plugin as root.\n", zcfg->domain);
      _exit(125);
    }

    if (x->program_user) {
      if (!prog_user_found) { _exit(126); }
      if (geteuid() == 0) {
        if (setgroups(0, NULL) != 0) _exit(126);
        if (setgid(prog_gid) != 0) _exit(126);
        if (setuid(prog_uid) != 0) _exit(126);
      } else if (prog_uid != geteuid() || prog_uid != getuid()) {
        // 非root起動では別ユーザーへ切り替えられない。main()の起動前検証
        // (validate_program_zone_users) で弾かれるはずだが念のため fail-closed。
        fprintf(stderr, "[FATAL] Zone '%s': program-user '%s' differs from the non-root user "
                "karidns runs as; refusing to exec plugin.\n", zcfg->domain, x->program_user);
        _exit(126);
      }
    }

    char *argv[64];
    int ai = 0;
    argv[ai++] = (char *)x->program_path;
    for (int i = 0; i < x->program_args_count && ai < 63; i++)
      argv[ai++] = x->program_args[i];
    argv[ai] = NULL;

    /* The plugin runs in "/", as it did when daemonize() changed there: it must not inherit the working directory of the server (the
     * starting directory or options { directory }, which program-user may not even be able to read) */
    if (chdir("/") != 0) _exit(126);

    /* バックエンドが無視/ブロックしているシグナルをプラグインへ引き継がない
     * (無視の設定とシグナルマスクは exec 後も残る) */
    signal(SIGPIPE, SIG_DFL);
    signal(SIGHUP, SIG_DFL);
    signal(SIGUSR1, SIG_DFL);
    signal(SIGUSR2, SIG_DFL);
    sigset_t plugin_mask;
    sigemptyset(&plugin_mask);
    sigprocmask(SIG_SETMASK, &plugin_mask, NULL);

    execve(x->program_path, argv, plugin_envp);   /* S-1: an empty environment (plugin_envp, built before the fork) */
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
  cap_rights_t rights_pd;
  cap_rights_init(&rights_pd, CAP_PDKILL);
  cap_rights_limit(proc_fd, &rights_pd);
#endif

  strncpy(out->domain, zcfg->domain, sizeof(out->domain) - 1);
  out->domain[sizeof(out->domain) - 1] = '\0';
  strlcpy(out->view_name, view_name ? view_name : "", sizeof(out->view_name));
  out->pid = pid;
  out->proc_fd = proc_fd;
  out->stdin_fd = in_pipe[1];
  out->stdout_fd = out_pipe[0];
  pthread_mutex_init(&out->lock, NULL);
  out->timeout_ms = x->program_timeout_ms > 0 ? x->program_timeout_ms : 2000;
  out->max_failures = x->program_max_failures > 0 ? x->program_max_failures : 5;
  out->disable_auto_tc_flag = x->disable_auto_tc_flag;
  compute_program_zone_fingerprint(zcfg, out->config_fingerprint, sizeof(out->config_fingerprint));
  atomic_init(&out->consecutive_failures, 0);
  atomic_init(&out->dead, false);

  syslog(LOG_INFO, "[Plugin] Spawned program zone '%s' -> pid=%d exec='%s'",
         zcfg->domain, pid, x->program_path);
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
    backend_exit(EXIT_FAILURE); /* O-15: スレッド起動後に Backend から呼ばれる */
  }

  syslog(LOG_WARNING, "[Plugin] %d program zone(s) enabled. "
         "This is a TEST-ONLY feature; do not use in production.", count);

  g_program_plugins = calloc(count, sizeof(program_plugin_t));
  if (!g_program_plugins) backend_exit(EXIT_FAILURE);

  int idx = 0;
  for (view_config_t *v = cfg->views; v; v = v->next) {
    for (zone_config_t *z = v->zones; z; z = z->next) {
      if (!z->type || strcasecmp(z->type, "program") != 0) continue;
      if (!zext(z)->program_path) {
        syslog(LOG_ERR, "[Plugin] zone '%s' has type program but no 'program' path set; skipping (will SERVFAIL)", z->domain);
        continue;
      }
      if (!zext(z)->program_user && cfg->user) {
        zone_ext_t *zx = zone_ext_mut(z);
        if (zx) zx->program_user = strdup(cfg->user);
      }
      if (spawn_one_program_plugin(z, v->name, &g_program_plugins[idx])) idx++;
    }
  }
  g_program_plugins_count = idx;
}

/* One view, by the address alone (the flat match-clients lists; an empty list matches every client) */
static bool view_match_addr(const view_snapshot_t *v, const char *client_ip) {
  if (v->match_clients_parsed && v->match_clients_count > 0) return check_acl_bin(client_ip, v->match_clients_parsed, v->match_clients_count);
  if (v->match_clients && v->match_clients_count > 0) return check_acl(client_ip, v->match_clients, v->match_clients_count);
  return true;
}

/* A view whose match-clients has a `key` element: the list is evaluated with the address and the TSIG key the request verified with (NULL: not
 * signed or not verified).  BIND dns_acl_allowed(): the first element that matches decides, a negated match denies, no match denies. */
static bool view_match_aml(const view_snapshot_t *v, const char *client_ip, const char *key) {
  return aml_allows_ip(v->match_aml, client_ip, key);
}

view_snapshot_t *select_view(zone_db_snapshot_t *snap, const char *client_ip) {
  if (!snap) return NULL;
  for (size_t i = 0; i < snap->view_count; i++) {
    view_snapshot_t *v = &snap->views[i];
    if (v->match_aml ? view_match_aml(v, client_ip, NULL) : view_match_addr(v, client_ip)) return v;
  }
  return NULL;
}

view_snapshot_t *select_view_req(zone_db_snapshot_t *snap, const server_config_t *cfg, const char *client_ip, const uint8_t *req,
                                 size_t req_len, tsig_request_t *tsig, bool *tsig_done) {
  *tsig_done = false;
  if (!snap) return NULL;
  /* only a message with an additional section can carry a TSIG (RFC 8945 §5.1) */
  const bool signed_possible = cfg && req && req_len >= DNS_HEADER_SIZE && (req[10] | req[11]) != 0;
  for (size_t i = 0; i < snap->view_count; i++) {
    view_snapshot_t *v = &snap->views[i];
    if (!v->match_aml) {
      if (view_match_addr(v, client_ip)) return v;
      continue;
    }
    /* BIND get_matching_view_sync(): the signature is checked against the ring of this view, and the identity (the key name) is known only
     * when that succeeds */
    bool checked = false;
    const char *key = NULL;
    if (signed_possible) {
      tsig_check_request_nolog(cfg, v->name, req, req_len, tsig);
      checked = tsig->status != TSIG_REQ_NONE;
      if (tsig->status == TSIG_REQ_VALID && tsig->key) key = tsig->key->name;
    }
    if (view_match_aml(v, client_ip, key)) {
      if (checked) {
        tsig_log_request_error(tsig, client_ip);
        *tsig_done = true;
      }
      return v;
    }
  }
  return NULL;
}

/* ============================================================================
 * 共有の応答キャッシュ (全ワーカーで 1 つ、問い合わせで作った応答を入れる)
 *
 * 以前はゾーンを読み込むたびに全レコードの応答を resolve_name() で作り、ゾーンの arena に
 * 持っていた (読み込み時間の大半、メモリはゾーン数とレコード数に比例)。ここでは応答本体
 * (answer/authority/additional、OPT の前まで) を、実際に問い合わせが来た名前だけ、大きさが
 * 決まった表に入れる。
 * - 起動時に 1 回確保する (response-cache-size)。クエリの経路では malloc しない。
 * - 表はセットの並び。セットは 8 件分の索引と 1 KiB のデータ領域を持ち、本体は 8 オクテット
 *   単位の可変長でデータ領域にリングバッファとして詰める (典型的な本体は 60-100 オクテット)。
 *   上書きした範囲を指す索引は消す (セットの中では古いものから追い出される)。
 * - セットごとの seqlock で守り、ロックは使わない (書き手が競合したら入れるのをやめるだけ、
 *   読み手は読む間に書き換わったら外れにする)。データは atomic の語単位で読み書きする。
 * - 鍵は (qname 小文字, qtype, qclass, ゾーンのデータの版, 設定の版) の SipHash-2-4。版は
 *   公開のたびに新しい値になるので、古い応答は引かれない (表全体を消す必要はない)。
 * ========================================================================== */
#define RCACHE_SET_ENTRIES 8
#define RCACHE_SET_WORDS 128 /* データ領域 1 KiB */
#define RCACHE_BODY_MAX 496  /* UDP 512 オクテットの応答から、ヘッダと最短の質問を除いた大きさ */

typedef struct {
  _Atomic uint64_t tag;    /* 鍵の SipHash。0 = 空き */
  _Atomic uint64_t gen;    /* ゾーンのデータの版 */
  _Atomic uint64_t counts; /* ancount | nscount << 16 | arcount << 32 */
  _Atomic uint32_t meta;   /* qtype << 16 | 本体の長さ */
  _Atomic uint32_t off;    /* データ領域の語の位置 */
} rcache_ent_t;

typedef struct {
  _Atomic uint32_t seq;  /* 偶数 = 安定、奇数 = 書き込み中 */
  _Atomic uint32_t head; /* 次に書く語の位置 (書き手だけが使う) */
  _Atomic uint32_t next; /* 空きが無いときに使う索引 (順に回す) */
  uint32_t pad;
  rcache_ent_t ent[RCACHE_SET_ENTRIES];
  _Atomic uint64_t data[RCACHE_SET_WORDS];
} rcache_set_t;

static rcache_set_t *g_rcache;
static size_t g_rcache_sets;
static uint64_t g_rcache_key[2];
static _Atomic uint64_t g_zone_data_generation = 1;

uint64_t zone_data_generation_next(void) {
  return atomic_fetch_add_explicit(&g_zone_data_generation, 1, memory_order_relaxed);
}

size_t response_cache_init(size_t bytes) {
  free(g_rcache);
  g_rcache = NULL;
  g_rcache_sets = 0;
  size_t sets = bytes / sizeof(rcache_set_t);
  if (sets == 0 || sets > UINT32_MAX) return 0;
  rcache_set_t *t = calloc(sets, sizeof(rcache_set_t));
  if (!t) return 0;
  arc4random_buf(g_rcache_key, sizeof(g_rcache_key));
  g_rcache_sets = sets;
  g_rcache = t;
  return sets * sizeof(rcache_set_t);
}

static uint64_t rcache_tag(const char *qname_lc, uint16_t qtype, uint16_t qclass, uint64_t gen, uint64_t cfg_gen) {
  uint8_t buf[DNS_NAME_TEXT_SIZE + 24];
  size_t n = strnlen(qname_lc, DNS_NAME_TEXT_SIZE);
  memcpy(buf, qname_lc, n);
  buf[n++] = (uint8_t)(qtype >> 8);
  buf[n++] = (uint8_t)qtype;
  buf[n++] = (uint8_t)(qclass >> 8);
  buf[n++] = (uint8_t)qclass;
  memcpy(buf + n, &gen, sizeof(gen));
  n += sizeof(gen);
  memcpy(buf + n, &cfg_gen, sizeof(cfg_gen));
  n += sizeof(cfg_gen);
  uint64_t t = dns_siphash24(buf, n, g_rcache_key);
  return t ? t : 1; /* 0 は空きの印 */
}

/* セット数は 2 の冪に限らない (設定した大きさを切り捨てない)。上位 32 ビットを掛けて割り当てる */
static rcache_set_t *rcache_set_of(uint64_t tag) {
  return &g_rcache[(size_t)(((tag >> 32) * (uint64_t)g_rcache_sets) >> 32)];
}

/* 見つかれば本体を dst に写して長さを返す。無い/入りきらない/書き込み中なら -1 */
STATIC_TEST int rcache_lookup(uint64_t tag, uint64_t gen, uint16_t qtype, uint8_t *dst, size_t room,
                         uint16_t *an, uint16_t *ns, uint16_t *ar) {
  rcache_set_t *set = rcache_set_of(tag);
  uint32_t s1 = atomic_load_explicit(&set->seq, memory_order_acquire);
  if (s1 & 1) return -1;
  for (int i = 0; i < RCACHE_SET_ENTRIES; i++) {
    rcache_ent_t *e = &set->ent[i];
    if (atomic_load_explicit(&e->tag, memory_order_relaxed) != tag ||
        atomic_load_explicit(&e->gen, memory_order_relaxed) != gen) continue;
    uint32_t meta = atomic_load_explicit(&e->meta, memory_order_relaxed);
    if ((meta >> 16) != qtype) continue;
    size_t len = meta & 0xFFFF;
    size_t off = atomic_load_explicit(&e->off, memory_order_relaxed);
    /* 書き換え中の値でもデータ領域の外は読まない (seq の確認は読んだ後) */
    if (len == 0 || len > RCACHE_BODY_MAX || len > room || off + (len + 7) / 8 > RCACHE_SET_WORDS) return -1;
    uint64_t counts = atomic_load_explicit(&e->counts, memory_order_relaxed);
    for (size_t w = 0; w * 8 < len; w++) {
      uint64_t word = atomic_load_explicit(&set->data[off + w], memory_order_relaxed);
      size_t chunk = len - w * 8 < 8 ? len - w * 8 : 8;
      memcpy(dst + w * 8, &word, chunk);
    }
    atomic_thread_fence(memory_order_acquire);
    if (atomic_load_explicit(&set->seq, memory_order_relaxed) != s1) return -1; /* 読む間に書き換わった */
    *an = (uint16_t)counts;
    *ns = (uint16_t)(counts >> 16);
    *ar = (uint16_t)(counts >> 32);
    return (int)len;
  }
  return -1;
}

STATIC_TEST void rcache_store(uint64_t tag, uint64_t gen, uint16_t qtype, const uint8_t *body, size_t len,
                         uint16_t an, uint16_t ns, uint16_t ar) {
  if (len == 0 || len > RCACHE_BODY_MAX) return;
  rcache_set_t *set = rcache_set_of(tag);
  uint32_t s0 = atomic_load_explicit(&set->seq, memory_order_relaxed);
  if ((s0 & 1) || !atomic_compare_exchange_strong_explicit(&set->seq, &s0, s0 + 1, memory_order_relaxed,
                                                          memory_order_relaxed))
    return; /* 他のワーカーが書いている: 入れない */
  atomic_thread_fence(memory_order_release);
  uint32_t words = (uint32_t)((len + 7) / 8);
  uint32_t off = atomic_load_explicit(&set->head, memory_order_relaxed);
  if (off + words > RCACHE_SET_WORDS) off = 0; /* 末尾に入らなければ先頭から */
  /* 上書きする範囲を指す索引と、同じ鍵の古い索引を消す。空いた索引を使う */
  int slot = -1;
  for (int i = 0; i < RCACHE_SET_ENTRIES; i++) {
    rcache_ent_t *e = &set->ent[i];
    uint64_t t = atomic_load_explicit(&e->tag, memory_order_relaxed);
    if (t != 0) {
      uint32_t eo = atomic_load_explicit(&e->off, memory_order_relaxed);
      uint32_t ew = ((atomic_load_explicit(&e->meta, memory_order_relaxed) & 0xFFFF) + 7) / 8;
      if (t == tag || (eo < off + words && off < eo + ew)) {
        atomic_store_explicit(&e->tag, 0, memory_order_relaxed);
        t = 0;
      }
    }
    if (t == 0 && slot < 0) slot = i;
  }
  if (slot < 0) {
    uint32_t n = atomic_load_explicit(&set->next, memory_order_relaxed);
    slot = (int)(n % RCACHE_SET_ENTRIES);
    atomic_store_explicit(&set->next, n + 1, memory_order_relaxed);
  }
  for (uint32_t w = 0; w < words; w++) {
    uint64_t word = 0;
    size_t chunk = len - w * 8 < 8 ? len - w * 8 : 8;
    memcpy(&word, body + w * 8, chunk);
    atomic_store_explicit(&set->data[off + w], word, memory_order_relaxed);
  }
  rcache_ent_t *e = &set->ent[slot];
  atomic_store_explicit(&e->tag, tag, memory_order_relaxed);
  atomic_store_explicit(&e->gen, gen, memory_order_relaxed);
  atomic_store_explicit(&e->meta, ((uint32_t)qtype << 16) | (uint32_t)len, memory_order_relaxed);
  atomic_store_explicit(&e->off, off, memory_order_relaxed);
  atomic_store_explicit(&e->counts, (uint64_t)an | ((uint64_t)ns << 16) | ((uint64_t)ar << 32), memory_order_relaxed);
  atomic_store_explicit(&set->head, off + words, memory_order_relaxed);
  atomic_store_explicit(&set->seq, s0 + 2, memory_order_release);
}

/* 公開する直前に呼ぶ。このゾーンの応答を共有キャッシュに入れてよいかを決める (応答がクライアントの
 * アドレス、ECS、時刻で変わるゾーンは入れない)。 */
void build_zone_response_cache(zone_version_t *arena, server_config_t *cfg, const zone_db_entry_t *entry) {
  if (!arena) return;
  arena->rcache_ok = false;
  atomic_store_explicit(&arena->generation, zone_data_generation_next(), memory_order_release); /* 公開する版ごとに 1 回 */
  const zone_image_t *img = arena->image; /* zone_image_freeze() の後で呼ぶ */
  if (!img || img->n_rrs == 0) return;
  if (img->flags & ZONE_IMAGE_F_TINYDNS) return;
  if (zone_image_has_zattr(img)) { /* tinydns locations, $LOCATION / $ECS-SUBNET tag definitions: the answer depends on the client (trusted resolvers alone do not) */
    int nloc = 0;
    zone_image_tags_t lt, et;
    (void)zone_image_locations(img, &nloc);
    zone_image_tags_open(img, ZONE_IMAGE_TAGS_LOCATION, &lt);
    zone_image_tags_open(img, ZONE_IMAGE_TAGS_ECS, &et);
    if (nloc > 0 || lt.left > 0 || et.left > 0) return;
  }
  if (cfg && cfg->wire_cache_max_records > 0 && img->n_rrs > cfg->wire_cache_max_records) return;

  // O-07: 同じゾーン名が別の view にもあるので、このエントリの view の設定を見る
  const zone_config_t *zcfg = zone_entry_config(cfg, entry);
  if (zcfg) {
    if (zext(zcfg)->location_tags != NULL && zext(zcfg)->location_tag_count > 0) return;
    if (zext(zcfg)->ecs_tags != NULL && zext(zcfg)->ecs_tag_count > 0) return;
    if (zcfg->type && strcasecmp(zcfg->type, "master") != 0 && strcasecmp(zcfg->type, "primary") != 0 &&
        strcasecmp(zcfg->type, "slave") != 0 && strcasecmp(zcfg->type, "secondary") != 0) return;
  }
  if (cfg) {
    if (cfg->location_tags != NULL && cfg->location_tag_count > 0) return;
    if (cfg->ecs_tags != NULL && cfg->ecs_tag_count > 0) return;
  }
  /* RR ごとの追加情報 (ext[]) に、応答がクライアントや時刻で変わるもの (location / ECS タグ、tinydns の時刻) があるか。
   * 大文字小文字だけ違う owner の綴りの印 (alt_text_off) は応答を変えない */
  for (uint32_t i = 0; i < img->n_ext; i++) {
    const zone_image_ext_t *e = &zone_image_exts(img)[i];
    if (e->loc_tag_off || e->ecs_tag_off || e->loc[0] || e->ttd || (e->flags & ZONE_IMAGE_EXT_COUNTDOWN))
      return;
  }
  arena->rcache_ok = true;
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

/* RFC 7873 §5.2.3: the response to a query whose Server Cookie is wrong: BADCOOKIE (RCODE 7 with the extended bits), AA=0, a fresh Server Cookie in the
 * OPT, nothing else.  The question is already copied to res[0..q_offset). */
static int build_badcookie_response(uint8_t *res, size_t max_res_len, uint16_t q_offset, edns_info_t *edns, uint8_t ext_rcode_out, bool is_tcp,
                                    server_config_t *cfg) {
  uint16_t offset = q_offset, arcount = 0;
  res[2] &= ~0x04; // RFC 7873 §5.2.3: AA MUST be 0
  res[3] = (res[3] & 0xF0) | 0x07; // BADCOOKIE (Base RCODE 7)
  if (edns->present) {
    assemble_edns_opt(res, max_res_len, &offset, &arcount, edns, ext_rcode_out, is_tcp, cfg);
  }
  res[6] = 0; res[7] = 0;
  res[8] = 0; res[9] = 0;
  res[10] = (uint8_t)(arcount >> 8);
  res[11] = (uint8_t)(arcount & 0xFF);
  return offset;
}

/* ---- Built-in CHAOS zones: version.bind, hostname.bind, id.server (BIND 9.20: bin/named/config.c defines them in the "_bind" view of class
 * CHAOS; bin/named/builtin.c answers them).  A zone has an SOA (MNAME = the zone, RNAME = hostmaster.<zone>, serial 0, 28800 7200 604800
 * 86400, TTL 86400), an NS at the apex (the zone itself, TTL 0) and, at the apex, a TXT of TTL 0 with the text of the option (version_lookup(),
 * hostname_lookup(), id_lookup()); no text (`none`, or server-id not written) leaves the apex without a TXT, so TXT is NODATA.  A name below
 * the apex is NXDOMAIN.  authors.bind is not served (BIND lists its authors there).  RFC 4892 §2: the identity of a server is asked for with
 * id.server / hostname.bind as TXT in class CHAOS.  The answers are built from the strings the parser resolved (chaos_finish()), into the
 * caller's buffer: no allocation. ---- */
static const char *const k_chaos_apex[3] = { "version.bind", "hostname.bind", "id.server" };

/* the built-in zone a name belongs to (index in k_chaos_apex), -1 for none; *at_apex: the name is the zone's apex */
static int chaos_zone_of(const char *qname, bool *at_apex) {
  size_t ql = dns_name_len_no_root(qname, strlen(qname));
  for (int i = 0; i < 3; i++) {
    size_t al = strlen(k_chaos_apex[i]);
    if (ql == al && strncasecmp(qname, k_chaos_apex[i], al) == 0) { *at_apex = true; return i; }
    if (ql > al + 1 && qname[ql - al - 1] == '.' && !dns_char_is_escaped(qname, ql - al - 1) && strncasecmp(qname + ql - al, k_chaos_apex[i], al) == 0) {
      *at_apex = false;
      return i;
    }
  }
  return -1;
}

/* append one RR (owner given as wire bytes, class CHAOS) to res; false when it does not fit below cap */
static bool chaos_put_rr(uint8_t *res, size_t cap, size_t *off, const uint8_t *owner, size_t owner_len, uint16_t type, uint32_t ttl,
                         const uint8_t *rdata, size_t rdlen) {
  if (*off + owner_len + 10 + rdlen > cap) return false;
  uint8_t *p = res + *off;
  memcpy(p, owner, owner_len);
  p += owner_len;
  *p++ = (uint8_t)(type >> 8); *p++ = (uint8_t)type;
  *p++ = 0; *p++ = 3;
  *p++ = (uint8_t)(ttl >> 24); *p++ = (uint8_t)(ttl >> 16); *p++ = (uint8_t)(ttl >> 8); *p++ = (uint8_t)ttl;
  *p++ = (uint8_t)(rdlen >> 8); *p++ = (uint8_t)rdlen;
  memcpy(p, rdata, rdlen);
  *off = (size_t)(p + rdlen - res);
  return true;
}

/* The answer for a question in class CHAOS about the built-in zone `zi` (the question is already copied to res[0..q_offset) and the header
 * flags are set, AA=1).  cap: room for the body (the OPT is reserved by the caller).  Returns the length of the whole response. */
static int chaos_build_response(const server_config_t *cfg, uint8_t *res, size_t cap, size_t max_res_len, size_t q_offset, int zi, bool at_apex,
                                uint16_t qtype, edns_info_t *edns, bool is_tcp, uint8_t ext_rcode_out, server_config_t *cfg_opt) {
  const chaos_cfg_t *c = &cfg->chaos;
  const bool has = zi == 0 ? c->has_version : zi == 1 ? c->has_hostname : c->has_id;
  const char *txt = zi == 0 ? c->r_version : zi == 1 ? c->r_hostname : c->r_id;
  uint8_t apex_w[32];
  long aw = write_uncompressed_name(apex_w, 0, sizeof(apex_w), k_chaos_apex[zi]);
  uint8_t soa[96];
  size_t sl = 0;
  if (aw > 0) {
    memcpy(soa, apex_w, (size_t)aw);                 /* MNAME */
    sl = (size_t)aw;
    soa[sl++] = 10;                                  /* RNAME: hostmaster.<zone> */
    memcpy(soa + sl, "hostmaster", 10);
    sl += 10;
    memcpy(soa + sl, apex_w, (size_t)aw);
    sl += (size_t)aw;
    static const uint32_t timers[5] = { 0, 28800, 7200, 604800, 86400 };   /* serial, refresh, retry, expire, minimum */
    for (int i = 0; i < 5; i++) {
      soa[sl++] = (uint8_t)(timers[i] >> 24); soa[sl++] = (uint8_t)(timers[i] >> 16);
      soa[sl++] = (uint8_t)(timers[i] >> 8); soa[sl++] = (uint8_t)timers[i];
    }
  }
  static const uint8_t qname_ptr[2] = { 0xC0, 0x0C };   /* the owner of an answer at the apex is the question's name */
  size_t off = q_offset;
  uint16_t an = 0, ns = 0;
  bool ok = aw > 0;
  if (ok && !at_apex) {
    res[3] = (res[3] & 0xF0) | 3;   /* NXDOMAIN */
    ok = chaos_put_rr(res, cap, &off, apex_w, (size_t)aw, 6, 86400, soa, sl);
    ns = ok ? 1 : 0;
  } else if (ok) {
    const bool any = qtype == 255;
    if ((any || qtype == 16) && has) {
      uint8_t td[CHAOS_TXT_MAX + 1];
      size_t tl = strlen(txt);
      td[0] = (uint8_t)tl;
      memcpy(td + 1, txt, tl);
      ok = chaos_put_rr(res, cap, &off, qname_ptr, 2, 16, 0, td, tl + 1);
      an += ok;
    }
    if (ok && (any || qtype == 6)) {
      ok = chaos_put_rr(res, cap, &off, qname_ptr, 2, 6, 86400, soa, sl);
      an += ok;
    }
    if (ok && (any || qtype == 2)) {
      ok = chaos_put_rr(res, cap, &off, qname_ptr, 2, 2, 0, apex_w, (size_t)aw);
      an += ok;
    }
    if (ok && an == 0) {   /* NODATA: the SOA tells the client how long to remember it */
      ok = chaos_put_rr(res, cap, &off, apex_w, (size_t)aw, 6, 86400, soa, sl);
      ns = ok ? 1 : 0;
    }
  }
  if (!ok) {   /* does not fit: nothing but the question, TC=1 (RFC 1035 §4.1.1) */
    off = q_offset;
    an = ns = 0;
    res[3] &= 0xF0;
    res[2] |= 0x02;
  }
  res[6] = (uint8_t)(an >> 8); res[7] = (uint8_t)an;
  res[8] = (uint8_t)(ns >> 8); res[9] = (uint8_t)ns;
  res[10] = 0; res[11] = 0;
  uint16_t offset16 = (uint16_t)off, arcount = 0;
  if (edns->present) {
    assemble_edns_opt(res, max_res_len, &offset16, &arcount, edns, ext_rcode_out, is_tcp, cfg_opt);
    res[10] = (uint8_t)(arcount >> 8);
    res[11] = (uint8_t)(arcount & 0xFF);
  }
  return offset16;
}

/* NOTIFY (RFC 1996; BIND lib/dns/zone.c dns_zone_notifyreceive(): the sender must be one of the
 * zone's primaries or match allow-notify): is client_ip one of the primaries listed in x, and, when that primary needs a TSIG key (its own `key`,
 * else the `keys` of the server statement covering the sender, else the zone's tsig-key: peer_key_name()), was the NOTIFY signed with it?  tkey = the key of a verified TSIG, or NULL. */
static bool notify_from_zone_primaries(const server_config_t *cfg, const char *view_name, const zone_ext_t *x, const char *client_ip,
                                        const tsig_key_t *tkey) {
  for (int k = 0; k < x->masters_count; k++) {
    if (!(x->masters_parsed ? cidr_entry_match_str(&x->masters_parsed[k], client_ip) : match_cidr(client_ip, x->masters[k].ip)))
      continue;
    /* the key by the precedence of the transfers (batch 5, peer_key_name()): the primaries element, the `keys` of the server statement
     * that covers the sender, the zone's tsig-key */
    const char *need = peer_key_name(x->masters[k].key, config_server_find_ip(cfg, view_name, client_ip), x->tsig_key);
    if (!need || (tkey && tsig_key_names_equal(tkey->name, need))) return true;
  }
  return false;
}

/* The same for a catalog member (RFC 9432: the member is a secondary of the catalog zone's
 * primaries).  The member has no zone { }, so zone_entry_config() is NULL for it: the primaries are those of its catalog zone, as the transfer
 * takes them (xfr_build_primaries()), and the single copy kept in the entry when the member was added is the fallback.  The TSIG rule is the
 * one of a configured secondary: the key of the primaries element, else the `keys` of the server statement, else the catalog zone's tsig-key. */
static bool notify_from_member_primaries(server_config_t *cfg, view_snapshot_t *view, const zone_db_entry_t *e, const char *client_ip,
                                         const tsig_key_t *tkey) {
  if (e->owning_catalog_domain) {
    zone_db_entry_t *cat = find_zone_in_view(view, e->owning_catalog_domain);
    const zone_config_t *cc = cat && domain_names_match_ci(cat->domain, e->owning_catalog_domain) ? zone_entry_config(cfg, cat) : NULL;
    if (cc && zext(cc)->masters_count > 0) return notify_from_zone_primaries(cfg, view->name, zext(cc), client_ip, tkey);
  }
  const catalog_master_t *m = e->catalog_master;
  if (!m || !m->ip[0] || !match_cidr(client_ip, m->ip)) return false;
  const char *need = peer_key_name(m->key, config_server_find_ip(cfg, view->name, client_ip), m->zone_key);
  return !need || (tkey && tsig_key_names_equal(tkey->name, need));
}

/* minimal-responses of the client's view (lib/ns/query.c: client->view->minimalresponses), else options'; no-auth-recursive is no-auth for a query with RD set and
 * no for the others (ns_query_start()), so the mode returned is the one an answer is built with */
static int query_minimal_mode(const server_config_t *cfg, const view_snapshot_t *view, const uint8_t *req) {
  int mode = MINIMAL_NO;
  if (cfg) {
    const view_config_t *mr_view = (cfg->any_view_minimal && view) ? config_find_view(cfg, view->name) : NULL;
    mode = config_minimal_responses(cfg, mr_view);
    if (mode == MINIMAL_NO_AUTH_RECURSIVE) mode = (req[2] & 0x01) ? MINIMAL_NO_AUTH : MINIMAL_NO;
  }
  return mode;
}

/* The wire name at p (uncompressed, from the apex block) as text, for the directory lookup of an NS target. */
static bool apex_name_text(const uint8_t *p, size_t len, char *out, size_t cap) {
  size_t next;
  return extract_wire_name_to_buffer(p, len, 0, &next, out, cap) >= 0;
}

/* Two uncompressed wire names (RFC 1035 3.1) are the same name: labels compared without regard to case (RFC 4343 2.1). */
static bool wire_names_equal_ci(const uint8_t *a, const uint8_t *b) {
  for (;;) {
    uint8_t l = *a;
    if (l != *b) return false;
    if (l == 0) return true;
    for (uint8_t i = 1; i <= l; i++) {
      uint8_t x = a[i], y = b[i];
      if (x >= 'A' && x <= 'Z') x = (uint8_t)(x + 32);
      if (y >= 'A' && y <= 'Z') y = (uint8_t)(y + 32);
      if (x != y) return false;
    }
    a += (size_t)l + 1;
    b += (size_t)l + 1;
  }
}

/* The size an answer may have on UDP when the query has EDNS: the size the client announced (512 at least) and no more than the server's limit (udp-bufsize,
 * zone-udp-bufsize, view max-udp-size, the `server` statement of the client: RFC 6891 6.2.3, 6.2.5), the capacity of res when it is known.  Clamps edns->udp_payload_size
 * too.  The limit the caller passed stays when the query has no EDNS, comes by TCP, or the caller's own buffer is smaller than a plain UDP answer (res[] must not be
 * written past its end).  One function for the answer of a zone in memory and for the answer from a summary: the two give the same bytes. */
static size_t edns_udp_limit(edns_info_t *edns, bool is_tcp, const server_config_t *cfg, const view_snapshot_t *view, const char *client_ip, size_t max_res_len,
                             size_t res_cap) {
  if (!edns->present) return max_res_len;
  if (edns->udp_payload_size < 512) edns->udp_payload_size = 512;
  if (is_tcp) return max_res_len;
  uint16_t server_udp_size = edns->server_udp_size ? edns->server_udp_size : KARIDNS_UDP_BUFSIZE_DEFAULT;
  /* the server statement of the client can set the limit (batch 5; BIND ns client.c: max-udp-size of the peer replaces the view's
   * for this client, 512..4096).  Only looked for when some statement writes it; no allocation (inet_pton on the text address). */
  if (cfg && cfg->any_server_max_udp) {
    const server_stmt_t *psrv = config_server_find_ip(cfg, view ? view->name : NULL, client_ip);
    if (psrv && (psrv->set & SV_MAX_UDP_SIZE)) server_udp_size = (uint16_t)psrv->max_udp_size;
  }
  if (edns->udp_payload_size > server_udp_size) edns->udp_payload_size = server_udp_size;
  /* UDP 応答の上限はクライアントが OPT で通知したサイズ (512 以上に丸め、サーバーの
   * udp-bufsize 以下。RFC 6891 §6.2.3、§6.2.5)。呼び出し側の max_res_len が大きくても小さくても
   * 置き換える (以前は 512 ちょうどのとき呼び出し側の値のままで、非同期経路では 4096 まで
   * 返しえた)。呼び出し側が 512 未満の小さなバッファを渡したときは広げない (res[] の範囲外へ
   * 書き込むため)。res_cap が分かっていればそれを超えない。 */
  if (max_res_len >= UDP_DEFAULT_MAX_RES_LEN) {
    max_res_len = edns->udp_payload_size;
    if (res_cap != 0 && max_res_len > res_cap) max_res_len = res_cap;
  }
  return max_res_len;
}

/* D1a step 6 (design 12-12): the answer to an SOA question at the apex of a zone that is not in memory, from the apex its summary brought.  It is what the
 * zone in memory gives, byte for byte: the SOA RR in Answer (RFC 1035 3.3.13, the names compressed as the zone image's serializer does, RFC 1035 4.1.4)
 * and, unless minimal-responses leaves it out, the NS RRset in Authority (RFC 1034 4.3.2 step 3a); the TTLs are the RRs' own (RFC 2181 5.2: the
 * NS RRset has the lowest of them).  A zone in memory also adds the addresses of the NS targets it serves to Additional (glue, RFC 2181 9 allows it,
 * and BIND does), and those are not in the summary: an NS target that a zone of this view contains (this zone, or a sibling) makes the summary
 * insufficient, and so does everything else the body of a query does that the summary cannot (a cookie, ECS, DO = 1: RRSIGs, MQTYPE ...): the query
 * then waits for the zone as before.  Returns the length of the response, or -1: not answered from the summary (nothing was written that matters). */
static int build_apex_soa_answer(const uint8_t *req, size_t req_len, uint8_t *res, size_t max_res_len, const zdir_elem_t *elem, const zdir_apex_t *ap,
                                 edns_info_t *edns, bool is_tcp, int minimal_mode, additional_from_auth_t policy, view_snapshot_t *view, compress_ctx_t *comp_ctx,
                                 const tsig_request_t *tsig, server_config_t *cfg) {
  if (ap->serial != zdir_serial(elem) || ap->n_ns == 0) return -1;
  if (edns->present && (edns->version != 0 || edns->dnssec_ok || edns->compact_answers_ok || edns->has_mqtype_query || edns->has_ecs || edns->has_malformed_ecs ||
                        edns->has_karidns_ext || edns->has_cookie || edns->has_malformed_cookie || edns->ede_count != 0 || edns->has_expire_query || edns->has_expire_value))
    return -1;
  size_t q_end;
  if (skip_wire_name(req, req_len, DNS_HEADER_SIZE, &q_end) != 0 || q_end + 4 > req_len) return -1;
  if (((req[q_end + 2] << 8) | req[q_end + 3]) != 1) return -1;                  // (class IN)
  size_t q_offset = q_end + 4;
  const uint8_t *ns = ap->data + ap->mname_len + ap->rname_len;
  const bool with_ns = minimal_mode == MINIMAL_NO;
  /* the glue the zone in memory adds (append_glue_records()): the addresses of the NS targets, from the zone itself and, when the target is in another zone of
   * the view, from that zone.  The summary has the addresses of the targets inside this zone; a target that another zone of the view holds (a sibling, or this
   * zone's own name below a zone cut that is a zone of the view) makes the summary insufficient.  additional-from-auth: no = none at all, in-domain = only
   * the targets at or below the apex. */
  const bool with_glue = with_ns && policy != ADDITIONAL_AUTH_NO;
  if (with_glue) {
    char nm[DNS_NAME_TEXT_SIZE];
    for (size_t off = 0, k = 0; k < ap->n_ns; k++) {
      size_t nl = 0;
      while (off + nl < ap->ns_len && ns[off + nl] != 0) nl += (size_t)ns[off + nl] + 1;
      nl++;
      if (off + nl > ap->ns_len || !apex_name_text(ns + off, nl, nm, sizeof(nm))) return -1;
      off += nl;
      const bool in_zone = domain_name_is_at_or_below(nm, elem->name);
      if (policy == ADDITIONAL_AUTH_IN_DOMAIN && !in_zone) continue;
      zdir_elem_t *pe = NULL;
      zone_db_entry_t *ze = find_zone_for_query_ex(view, nm, 1, &pe);
      if (ze != NULL || (pe != NULL && pe != elem) || (in_zone && pe != elem)) return -1;
    }
  }
  size_t limit = max_res_len;                               /* what the body may use: the room for the OPT (RFC 6891 7) and for the TSIG (RFC 8945 5.3) is kept back */
  if (tsig) {
    size_t reserve = tsig_response_reserve(tsig);
    if (reserve > 0 && limit > reserve + DNS_HEADER_SIZE) limit -= reserve;
  }
  size_t body_max = limit;
  if (edns->present) {
    size_t opt_reserve = edns_opt_reserve_len(edns, is_tcp, cfg);
    if (limit > opt_reserve + DNS_HEADER_SIZE) body_max = limit - opt_reserve;
  }
  if (q_offset > body_max || body_max > UINT16_MAX) return -1;
  memcpy(res, req, q_offset);
  compress_ctx_init_packet(comp_ctx);
  register_wire_name_for_compression(res, DNS_HEADER_SIZE, comp_ctx);
  dns_init_response_header(res, req, 0, true);
  uint16_t offset = (uint16_t)q_offset, ancount = 0, nscount = 0, arcount = 0;
  /* SOA */
  if (apex_write_soa_rr(res, &offset, body_max, elem->name, ap, comp_ctx) != 0) return -1;
  uint32_t v;
  uint16_t rdl_at;
  ancount = 1;
  /* NS */
  if (with_ns) {
    const uint8_t *t = ns;
    for (unsigned k = 0; k < ap->n_ns; k++) {
      size_t nl = 0;
      while (t[nl] != 0) nl += (size_t)t[nl] + 1;
      nl++;
      if (write_dns_name_str(res, &offset, elem->name, comp_ctx, body_max) != 0 || (size_t)offset + 10 > body_max) return -1;
      res[offset++] = 0; res[offset++] = 2; res[offset++] = 0; res[offset++] = 1;
      v = ap->ns_ttl;
      res[offset++] = (uint8_t)(v >> 24); res[offset++] = (uint8_t)(v >> 16); res[offset++] = (uint8_t)(v >> 8); res[offset++] = (uint8_t)v;
      rdl_at = offset;
      offset += 2;
      if (compress_name(res, &offset, t, comp_ctx, body_max) != 0) return -1;
      res[rdl_at] = (uint8_t)((offset - rdl_at - 2) >> 8);
      res[rdl_at + 1] = (uint8_t)(offset - rdl_at - 2);
      nscount++;
      t += nl;
    }
  }
  /* the addresses of the NS targets inside the zone, in the order of the NS RRs and, for one target, of the zone (RFC 2181 9: the addresses of a name are all
   * there or none; the first target whose addresses do not fit ends the glue, without TC) */
  if (with_glue && ap->glue_len > 0) {
    const uint8_t *g = ns + ap->ns_len, *gend = g + ap->glue_len, *t = ns;
    for (unsigned k = 0; k < ap->n_ns && g < gend; k++) {
      size_t nl = 0;
      while (t[nl] != 0) nl += (size_t)t[nl] + 1;
      nl++;
      bool dup = false;                                      /* (the same target twice: one set of addresses) */
      for (const uint8_t *u = ns; u < t && !dup; ) {
        size_t ul = 0;
        while (u[ul] != 0) ul += (size_t)u[ul] + 1;
        ul++;
        dup = ul == nl && wire_names_equal_ci(u, t);
        u += ul;
      }
      const uint16_t so = offset, sa = arcount;
      bool fits = true;
      while (g < gend && g[0] == k) {
        const size_t al = g[1] == 1 ? 4 : 16;
        if (!dup) {
          if (compress_name(res, &offset, t, comp_ctx, body_max) != 0 || (size_t)offset + 10 + al > body_max) {
            fits = false;
            break;
          }
          res[offset++] = 0; res[offset++] = g[1]; res[offset++] = 0; res[offset++] = 1;
          memcpy(res + offset, g + 2, 4);
          offset += 4;
          res[offset++] = 0; res[offset++] = (uint8_t)al;
          memcpy(res + offset, g + 6, al);
          offset += (uint16_t)al;
          arcount++;
        }
        g += 6 + al;
      }
      if (!fits) {
        offset = so;
        arcount = sa;
        break;
      }
      t += nl;
    }
  }
  if (edns->present) assemble_edns_opt(res, limit, &offset, &arcount, edns, 0, is_tcp, cfg);
  res[4] = 0; res[5] = 1;
  res[6] = (uint8_t)(ancount >> 8); res[7] = (uint8_t)ancount;
  res[8] = (uint8_t)(nscount >> 8); res[9] = (uint8_t)nscount;
  res[10] = (uint8_t)(arcount >> 8); res[11] = (uint8_t)arcount;
  return offset;
}

/* SERVFAIL with Extended DNS Error 14 "Not Ready" (RFC 8914 4.15), keeping the question: the answer for a query whose zone is in the directory
 * and cannot be had in time (D1a design 4.4).  The request's own EDE options are not echoed.  Signing is the caller's (the TSIG handling around
 * process_query_body()). */
static int build_not_ready_response(const uint8_t *req, size_t req_len, uint8_t *res, size_t cap, bool is_tcp, server_config_t *cfg) {
  if (req_len < DNS_HEADER_SIZE) return 0;
  edns_info_t edns;
  edns_info_reset(&edns);
  edns.present = false;
  uint16_t qd = (uint16_t)((req[4] << 8) | req[5]), an = (uint16_t)((req[6] << 8) | req[7]);
  uint16_t ns = (uint16_t)((req[8] << 8) | req[9]), ar = (uint16_t)((req[10] << 8) | req[11]);
  if (parse_edns_opt(req, req_len, qd, an, ns, ar, &edns) == 0) edns.ede_count = 0;      /* (reflection: the request's own EDE is not echoed) */
  add_ede(&edns, cfg ? cfg->send_extended_errors : false, 14, "Not Ready");
  return dns_build_error_response(req, req_len, res, cap, 2 /* SERVFAIL */, 0, 1, &edns, is_tcp, cfg);
}

int process_dns_query_impl(const uint8_t *req, size_t req_len, uint8_t *res,
                            size_t max_res_len, const char *qname, uint16_t qtype,
                            const char *client_ip, compress_ctx_t *comp_ctx,
                            bool is_tcp, const rate_limit_config_t **out_rrl_cfg,
                            zone_db_snapshot_t *snap, server_config_t *cfg,
                            zone_db_entry_t **out_matched_entry) {
  return process_dns_query_impl_cap(req, req_len, res, max_res_len, 0, qname, qtype, client_ip, comp_ctx,
                                    is_tcp, out_rrl_cfg, snap, cfg, out_matched_entry);
}

static int process_query_body(const uint8_t *req, size_t req_len, uint8_t *res,
                              size_t max_res_len, size_t res_cap, const char *qname, uint16_t qtype,
                              const char *client_ip, compress_ctx_t *comp_ctx,
                              bool is_tcp, const rate_limit_config_t **out_rrl_cfg,
                              zone_db_snapshot_t *snap, server_config_t *cfg,
                              zone_db_entry_t **out_matched_entry, tsig_request_t *tsig,
                              const query_route_t *route, const zdir_elem_t *not_ready_zone);

static int process_dns_query_impl_cap_routed(const uint8_t *req, size_t req_len, uint8_t *res,
                                             size_t max_res_len, size_t res_cap, const char *qname, uint16_t qtype,
                                             const char *client_ip, compress_ctx_t *comp_ctx,
                                             bool is_tcp, const rate_limit_config_t **out_rrl_cfg,
                                             zone_db_snapshot_t *snap, server_config_t *cfg,
                                             zone_db_entry_t **out_matched_entry, const query_route_t *route,
                                             const zdir_elem_t *not_ready_zone);

int process_dns_query_impl_cap(const uint8_t *req, size_t req_len, uint8_t *res,
                               size_t max_res_len, size_t res_cap, const char *qname, uint16_t qtype,
                               const char *client_ip, compress_ctx_t *comp_ctx,
                               bool is_tcp, const rate_limit_config_t **out_rrl_cfg,
                               zone_db_snapshot_t *snap, server_config_t *cfg,
                               zone_db_entry_t **out_matched_entry) {
  return process_dns_query_impl_cap_routed(req, req_len, res, max_res_len, res_cap, qname, qtype, client_ip, comp_ctx,
                                           is_tcp, out_rrl_cfg, snap, cfg, out_matched_entry, NULL, NULL);
}

/* res_cap: res の実際の容量 (バイト)。0 なら不明で、従来どおり max_res_len (UDP では EDNS の
 * サイズに置き換えた後の値) を容量とみなす。max_res_len は応答の上限 (UDP ではクライアントの上限)。 */
/* RFC 8945 §5.2、§5.3: TSIG の付いた要求は、どの OPCODE でも先に TSIG を検証し (鍵は要求の鍵名と
 * アルゴリズムで決める)、TSIG RR を除いた要求を処理して、応答に TSIG を付ける (検証できれば同じ鍵で
 * 署名、鍵と MAC のエラーは無署名)。TSIG のエラーは NOTAUTH、解釈できない TSIG は FORMERR。 */
static int process_dns_query_impl_cap_routed(const uint8_t *req, size_t req_len, uint8_t *res,
                                             size_t max_res_len, size_t res_cap, const char *qname, uint16_t qtype,
                                             const char *client_ip, compress_ctx_t *comp_ctx,
                                             bool is_tcp, const rate_limit_config_t **out_rrl_cfg,
                                             zone_db_snapshot_t *snap, server_config_t *cfg,
                                             zone_db_entry_t **out_matched_entry, const query_route_t *route,
                                             const zdir_elem_t *not_ready_zone) {
  t_query_rrl_info.zone = NULL; /* D-05: 早い段階で返す応答 (エラー) のために先に消す */
  t_query_rrl_info.wildcard = false;
  if (req_len < DNS_HEADER_SIZE) {
    t_qacl.local_valid = t_qacl.client_valid = false;
    return 0; // 不正な短いパケットは無応答で破棄
  }
  tsig_request_t tsig;
  /* The view is chosen first, once, here when the caller has not (select_view_req(): by the client address, and by the TSIG key for a view whose
   * match-clients has a `key`, BIND get_matching_view_sync()); the body takes it with its zone.  Then the key of the request is looked for
   * among the global keys and that view's own (dns_message_checksig(message, view) with the view's ring): not again when select_view_req()
   * has made that very check (route->tsig).  Only a message that carries an additional section can be signed, so tsig_check_request()
   * returns at once for the others. */
  query_route_t own_route;
  if (snap && !route) {
    bool done = false;
    own_route.view = select_view_req(snap, cfg, client_ip, req, req_len, &tsig, &done);
    zdir_elem_t *own_pel = NULL;
    own_route.entry = own_route.view ? find_zone_for_query_ex(own_route.view, qname, ((req[2] >> 3) & 0x0F) == 0 ? qtype : 0, &own_pel) : NULL;
    /* D1a: a zone that is in the directory and not in memory (TLS, DoH and the other callers that do not park): "not ready", not REFUSED */
    if (!own_route.entry && own_pel && !not_ready_zone) not_ready_zone = own_pel;
    own_route.tsig = done ? &tsig : NULL;
    route = &own_route;
  }
  if (route && route->tsig) {
    if (route->tsig != &tsig) tsig = *route->tsig;
  } else {
    tsig_check_request(cfg, route && route->view ? route->view->name : NULL, req, req_len, client_ip, &tsig);
  }
  t_query_tsig.status = TSIG_REQ_NONE; /* X-20: slip 応答の署名用。署名のない要求では使わない */
  if (tsig.status == TSIG_REQ_NONE) {
    int plain = process_query_body(req, req_len, res, max_res_len, res_cap, qname, qtype, client_ip, comp_ctx,
                                   is_tcp, out_rrl_cfg, snap, cfg, out_matched_entry, NULL, route, not_ready_zone);
    t_qacl.local_valid = t_qacl.client_valid = false;   /* the address of the next query is set by its transport */
    t_qacl.key = NULL;
    return plain;
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
                               is_tcp, out_rrl_cfg, snap, cfg, out_matched_entry, &tsig, route, not_ready_zone);
  t_qacl.local_valid = t_qacl.client_valid = false;
  t_qacl.key = NULL;
  if (ret < DNS_HEADER_SIZE) return ret;
  size_t limit = tsig.res_limit;
  if (res_cap != 0 && limit > res_cap) limit = res_cap;
  t_query_tsig = tsig;
  return tsig_finish_response(res, (size_t)ret, limit, &tsig);
}

static int process_query_body(const uint8_t *req, size_t req_len, uint8_t *res,
                              size_t max_res_len, size_t res_cap, const char *qname, uint16_t qtype,
                              const char *client_ip, compress_ctx_t *comp_ctx,
                              bool is_tcp, const rate_limit_config_t **out_rrl_cfg,
                              zone_db_snapshot_t *snap, server_config_t *cfg,
                              zone_db_entry_t **out_matched_entry, tsig_request_t *tsig,
                              const query_route_t *route, const zdir_elem_t *not_ready_zone) {
  char current_qname[DNS_NAME_TEXT_SIZE];
  strlcpy(current_qname, qname, sizeof(current_qname));
  char current_qname_lc[DNS_NAME_TEXT_SIZE];
  size_t current_qname_lc_len = 0;
  for (; current_qname[current_qname_lc_len] != '\0' && current_qname_lc_len < sizeof(current_qname_lc) - 1; current_qname_lc_len++) {
    char c = current_qname[current_qname_lc_len];
    current_qname_lc[current_qname_lc_len] = (c >= 'A' && c <= 'Z') ? (c | 0x20) : c;
  }
  current_qname_lc[current_qname_lc_len] = '\0';
  zone_version_t *current_zone = NULL;
  zone_db_entry_t *db_entry = NULL;
  view_snapshot_t *view = NULL;
  t_qacl.key = (tsig && tsig->status == TSIG_REQ_VALID && tsig->key) ? tsig->key->name : NULL;   /* `key <name>` in allow-query */

  if (snap && route) {
    /* E2: the view and the zone were looked up by the caller or by process_dns_query_impl_cap_routed() (query_route_t; with a snapshot there
     * is always a route).  R-32: a DS for a child apex is answered by the parent zone (QUERY only): find_zone_for_query() knows. */
    view = route->view;
    db_entry = route->entry;
  }

  /* E2: the zone's configuration, looked up once (it is a hash lookup by view and zone name).  The later users below see the same
   * result as before: matched_zcfg is NULL without cfg, zone_cfg_any is not (a DB zone's own configuration needs no cfg). */
  const zone_config_t *zone_cfg_any = (db_entry && view) ? zone_entry_config(cfg, db_entry) : NULL;
  const zone_config_t *matched_zcfg = cfg ? zone_cfg_any : NULL;
  /* D-05: RRL のキー (NXDOMAIN はゾーン名、ワイルドカードの答えは "*.<ゾーン>") */
  t_query_rrl_info.zone = db_entry ? db_entry->domain : NULL;
  t_query_rrl_info.wildcard = false;
  if (out_rrl_cfg) {
    *out_rrl_cfg = cfg ? &cfg->rrl : NULL;
    if (matched_zcfg && zext(matched_zcfg)->rrl.configured) {
      *out_rrl_cfg = &zext(matched_zcfg)->rrl;
    }
  }
  uint16_t qdcount = (req[4] << 8) | req[5],
           ancount_req = (req[6] << 8) | req[7],
           nscount_req = (req[8] << 8) | req[9],
           arcount_req = (req[10] << 8) | req[11];

  edns_info_t edns;
  edns_info_reset(&edns);
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
  if (matched_zcfg && zext(matched_zcfg)->zone_udp_bufsize > 0)
    edns.server_udp_size = zext(matched_zcfg)->zone_udp_bufsize;
  else {
    /* view { max-udp-size } replaces options' for the clients of the view (only looked up when some view writes it) */
    const view_config_t *vcfg = (cfg && cfg->any_view_max_udp && view) ? config_find_view(cfg, view->name) : NULL;
    if (vcfg && vcfg->max_udp_size) edns.server_udp_size = vcfg->max_udp_size;
    else if (cfg && cfg->udp_bufsize > 0) edns.server_udp_size = cfg->udp_bufsize;
  }

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

  if (edns_version_unsupported(&edns)) {
    // RFC 6891 §6.1.3: BADVERS。オプションの意味はバージョンごとに決まるので、オプションの不正より先に返す。
    // AXFR/IXFR の受付 (dns_server_core.c) も同じ順序 (TSIG の検証の後、他の検査の前) で同じ関数を使う (X-28)。
    return dns_build_badvers_response(req, req_len, res, max_res_len, qdcount, &edns, is_tcp, cfg);
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

  /* X-15, RFC 1035 §4.1.4: 最初の名前の圧縮ポインタは前に現れた名前を指せない (指せるのはヘッダだけ)。
   * 質問を写し返せないので QDCOUNT=0 の FORMERR (以前はポインタの先によって無応答、または別の名前の答え)。 */
  if (qdcount == 1 && wire_question_name_compressed(req, req_len)) {
    add_ede(&edns, send_ede, 0, NULL);
    return dns_build_error_response(req, req_len, res, max_res_len, 1, 0, 0, &edns, is_tcp, cfg); // FORMERR
  }

  if (not_ready_zone && qdcount == 1) {
    /* D1a: the zone is in the directory and its data is not in memory, and the caller cannot wait for it (or has waited in vain).  After the
     * checks of the message above (a malformed request is still a FORMERR), before any work on the zone.  The answer is an error answer of that
     * zone for rate limiting (the global limits), and goes through the TSIG handling of the caller like every other answer: signed with the
     * key of a verified request, RFC 8945 5.3 (the request given here has the TSIG record taken off, 5.2). */
    t_query_rrl_info.zone = not_ready_zone->name;
    /* the zone's own settings come from the interned block the element kept when its data left memory (zdir_elem_t.sh); only the ACL levels read them */
    zone_config_t zc;
    memset(&zc, 0, sizeof(zc));
    zc.domain = (char *)not_ready_zone->name;
    zone_ext_shared_t *nrsh = atomic_load_explicit(&not_ready_zone->sh, memory_order_acquire);
    zc.ext = nrsh ? &nrsh->ext : NULL;
    tsig_key_t *nr_tkey = (tsig && tsig->status == TSIG_REQ_VALID) ? tsig->key : NULL;
    if (opcode == 4) {
      /* NOTIFY: a primary zone accepts none (the same REFUSED as a zone in memory gives, RFC 1996 4.7; AA=0, RD=0).  Nothing is read for it and
       * nothing is counted: only a query (below) waits for a zone.  A zone that is a secondary is never taken out of memory. */
      add_ede(&edns, send_ede, 18, "Query refused due to access control");
      int len = dns_build_error_response(req, req_len, res, max_res_len, 5, 0, qdcount, &edns, is_tcp, cfg);
      if (len >= DNS_HEADER_SIZE) res[2] &= ~0x01;
      return len;
    }
    if (opcode == 5) {
      /* UPDATE (RFC 2136): the zone is checked as for a zone in memory (3.1.1, 3.1.2: SOA question, the apex of this zone), then allow-update from the
       * settings kept in the element.  An UPDATE that may be made is answered SERVFAIL + EDE 14 now: it is applied to the zone in memory, which a
       * later step reads for it (design 7); nothing waits and nothing is read for it here. */
      size_t zone_end = get_question_end_offset(req, req_len, 1);
      uint16_t zclass = (zone_end >= DNS_HEADER_SIZE + 5) ? (uint16_t)((req[zone_end - 2] << 8) | req[zone_end - 1]) : 0;
      int urc;
      if (qtype != 6) {
        urc = 1;                                        // FORMERR
      } else if (!view || zclass != 1 || !domain_names_match_ci(not_ready_zone->name, current_qname)) {
        urc = 9;                                        // NOTAUTH
      } else {
        bool uauth = zext(&zc)->upd_policy ? nr_tkey != NULL
                                           : (cfg && zone_update_acl_allows_in_view(cfg, &zc, view->name, client_ip, nr_tkey ? nr_tkey->name : NULL));
        if (uauth) {
          /* D1a milestone 4 (design 7, 12-8): an UPDATE that may be made waits for the zone like a query (parked, the zone is read), and is applied
           * to it when it is there; the zone then stays in memory (pinned) until the next load from the database.  Where nothing can wait (TLS, DoH,
           * a table that is full, the time is up) the client is told to try again. */
          if (t_nr_probe) return DNS_NR_PERMITTED;
          urc = 2;                                      // SERVFAIL, Not Ready
          add_ede(&edns, send_ede, 14, "Not Ready");
        } else {
          urc = 5;                                      // REFUSED
          add_ede(&edns, send_ede, 18, "Query refused due to access control");
        }
      }
      int len = dns_build_error_response(req, req_len, res, max_res_len, (uint8_t)urc, 0, qdcount, &edns, is_tcp, cfg);
      if (len >= DNS_HEADER_SIZE) res[2] &= ~0x01;
      return len;
    }
    /* allow-query first, exactly as for a zone in memory (below: once the zone is known, before anything else is done for the query): a client
     * that may not ask is refused, does not wait for the zone, does not make the server read it, and does not learn that the zone is in the
     * database. */
    if (opcode == 0 && view && cfg && cfg->acl_query_active && !zone_query_permitted(cfg, &zc, view->name, client_ip)) {
      add_ede(&edns, send_ede, 18, "Query refused due to access control");
      return dns_build_error_response(req, req_len, res, max_res_len, 5, 0, 1, &edns, is_tcp, cfg);
    }
    if (opcode == 0 && qtype == 6 && qdcount == 1 && view && domain_names_match_ci(not_ready_zone->name, current_qname)) {
      const zdir_apex_t *ap = atomic_load_explicit(&not_ready_zone->apex, memory_order_acquire);
      if (ap) {
        /* the size the zone in memory would answer with (the EDNS size of the client on UDP), and the TSIG signing needs the same limit */
        const size_t alimit = edns_udp_limit(&edns, is_tcp, cfg, view, client_ip, max_res_len, res_cap);
        const size_t tsig_limit = tsig ? tsig->res_limit : 0;
        if (tsig) tsig->res_limit = alimit;
        const additional_from_auth_t apolicy = zext(&zc)->additional_from_auth_specified ? zext(&zc)->additional_from_auth
                                                                                         : (cfg ? cfg->additional_from_auth : ADDITIONAL_AUTH_YES);
        int alen = build_apex_soa_answer(req, req_len, res, alimit, not_ready_zone, ap, &edns, is_tcp, query_minimal_mode(cfg, view, req), apolicy, view,
                                         comp_ctx, tsig, cfg);
        if (alen >= DNS_HEADER_SIZE) return alen;
        if (tsig) tsig->res_limit = tsig_limit;
      }
    }
    if (t_nr_probe && opcode == 0) return DNS_NR_PERMITTED;
    return build_not_ready_response(req, req_len, res, max_res_len, is_tcp, cfg);
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
      const zone_config_t *zc = zone_cfg_any;
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
      const zone_config_t *zcfg = zone_cfg_any;
      const zone_ext_t *zx = zext(zcfg);
      /* from one of the primaries, signed with that primary's key (else the zone's tsig-key) when it has one */
      if (zcfg && zx->masters_count > 0) auth = notify_from_zone_primaries(cfg, view->name, zx, client_ip, tkey);
      /* a catalog member has no zone { } of its own (or none with primaries): the primaries of its catalog zone */
      if (!auth && db_entry->is_catalog_member) auth = notify_from_member_primaries(cfg, view, db_entry, client_ip, tkey);
      /* allow-notify (BIND 9.20 ARM): "in addition to the zone primaries"; it applies to the secondary zones, from the zone, the view
       * or options.  A `key` element is the TSIG key the NOTIFY was signed with. */
      if (!auth && db_entry->is_secondary)
        auth = zone_notify_acl_allows(cfg, zcfg, view->name, client_ip, tkey ? tkey->name : NULL);
    }

    uint8_t notify_rcode = 0;
    if (auth) {
      atomic_store_explicit(&db_entry->refresh_now, true, memory_order_release);
      int kq = atomic_load_explicit(&g_control_kq, memory_order_acquire);
      if (kq != -1) {
        struct kevent ev;
        EV_SET(&ev, 2, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
        kevent(kq, &ev, 1, NULL, 0, NULL);
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
      const zone_config_t *zc = zone_cfg_any;
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
      const zone_config_t *zcfg = zone_cfg_any; /* zone_rcode == 0: db_entry and view are set */
      if (zcfg) {
        if (zcfg->type && (strcasecmp(zcfg->type, "master") == 0 || strcasecmp(zcfg->type, "primary") == 0)) {
          zone_is_master = true;
        }
      }
      /* the address list, the named keys, update-acl-match and (DB zones) acl-ceiling: dns_tsig_acl.c */
      /* update-policy replaces allow-update: the UPDATE must be signed, and the rules decide each change (handle_dynamic_update()) */
      if (zcfg) auth = zext(zcfg)->upd_policy ? tkey != NULL : zone_update_acl_allows_in_view(cfg, zcfg, view->name, client_ip, tkey ? tkey->name : NULL);
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

  max_res_len = edns_udp_limit(&edns, is_tcp, cfg, view, client_ip, max_res_len, res_cap);
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
          /* require-server-cookie (BIND lib/ns/query.c ns__query_start()): a UDP query that carries a client cookie but no valid server cookie gets
           * BADCOOKIE, with a new server cookie to repeat the query with (RFC 7873 §5.2.3); a query without a cookie option is answered as usual */
          if (!is_tcp && config_require_server_cookie(cfg, view ? view->name : NULL)) {
              is_badcookie = true;
              ext_rcode_out = 1;
          }
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
  /* allow-query / allow-query-on (BIND 9.20 ARM): the zone's statement, else the view's, else options'.  A client that may not ask
   * gets REFUSED (RFC 1035 §4.1.1) with EDE 18 Prohibited (RFC 8914 §4.19), as for a transfer or an update that is not allowed.  This is
   * the first thing done for a QUERY once the zone is known -- before the zone's expiry, the cached wire answers and every lookup --
   * and the answers in the shared response cache do not depend on the client, so the cache never has to know who may ask. */
  if (db_entry && view && cfg && cfg->acl_query_active && !zone_query_permitted(cfg, zone_cfg_any, view->name, client_ip)) {
    add_ede(&edns, send_ede, 18, "Query refused due to access control");
    return dns_build_error_response(req, req_len, res, max_res_len, 5, 0, 1, &edns, is_tcp, cfg);
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
  /* Built-in CHAOS zones (version.bind, hostname.bind, id.server).  BIND answers a CHAOS question from its "_bind" view whatever the zones of the
   * other views are, so this comes before the zone of the IN view.  A zone of the same name in the configuration is served instead.  allow-query
   * of options (or the view the client matches) applies, as BIND's configure_view_acl() gives the _bind view the options' ACLs. */
  if (qclass == 3 && cfg) {
    bool at_apex = false;
    int zi = chaos_zone_of(current_qname_lc, &at_apex);
    if (zi >= 0 && !(db_entry && domain_names_match_ci(db_entry->domain, k_chaos_apex[zi]))) {
      if (!zone_query_permitted(cfg, NULL, view ? view->name : NULL, client_ip)) {
        add_ede(&edns, send_ede, 18, "Query refused due to access control");
        return dns_build_error_response(req, req_len, res, max_res_len, 5, 0, 1, &edns, is_tcp, cfg);
      }
      if (is_badcookie) return build_badcookie_response(res, max_res_len, (uint16_t)q_offset, &edns, ext_rcode_out, is_tcp, cfg);
      return chaos_build_response(cfg, res, body_max_len, max_res_len, q_offset, zi, at_apex, qtype, &edns, is_tcp, ext_rcode_out, cfg);
    }
  }
  if (db_entry && view) {
    const zone_config_t *zcfg = zone_cfg_any;
    if (zcfg && zcfg->type && strcasecmp(zcfg->type, "program") == 0) {
      const rate_limit_config_t *rrl = zext(zcfg)->rrl.configured ? &zext(zcfg)->rrl : (cfg ? &cfg->rrl : NULL);
      if (!is_tcp && rrl && rrl->configured && rrl->early_drop) {
        struct sockaddr_storage ss;
        if (resolve_ip_port_to_sockaddr(client_ip, 0, &ss) > 0) {
          /* D-05: 応答を作る前なので、この名前・型への NOERROR のバケット (と all-per-second) を見る */
          rrl_key_t key = { .cls = RRL_RESP_NOERROR, .name = qname, .qtype = qtype, .qclass = qclass };
          if (rrl_key_exhausted(&ss, &key, rrl)) {
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

  if (!current_zone->image || current_zone->image->n_rrs == 0) {
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

  const zone_config_t *zcfg = zone_cfg_any;
  bool ecs_trusted = (cfg && cfg->ecs_enable && edns.has_ecs && client_ip &&
                      is_ecs_trusted_resolver(current_zone->image, cfg, zcfg, client_ip));

  /* B8t-1: a zone whose SOA RRs are restricted (tinydns location / time stamp, $LOCATION / $ECS-SUBNET tag) is served only to the
   * clients that see one of them. For the others it is a zone that is not served to them: REFUSED, AA=0, EDE 18 Prohibited
   * (RFC 1035 §4.1.1, RFC 8914 §4.19), as BIND 9.20 answers a client the zone is not served to (no matching view, allow-query
   * denial). The closest zone decides: there is no fall back to a parent zone's answer. tinydns differs (tdlookup.c: a
   * referral without AA, or no answer at all); documented in docs/karidns.md. */
  /* B8t-2: a SOA (or IXFR) question that carries the KariDNS extension option for this zone (a KariDNS secondary checking the serial)
   * is answered with the reference SOA, whatever location, tag or time the requester has: a secondary outside every SOA's location
   * must still be able to refresh.  The SOA of a zone is public data; the option adds nothing a plain query could not learn from a
   * client the zone is served to. */
  const bool ref_soa_ask = db_entry && (qtype == 6 || qtype == 251) && qclass == 1 && edns.has_karidns_ext &&
                           KARIDNS_EXT_VERSION_OK(edns.karidns_ext_version) &&
                           edns.karidns_ext_hash == calc_fnv1a_str(db_entry->domain) &&
                           domain_names_match_ci(current_qname_lc, db_entry->domain);

  if ((current_zone->image->flags & ZONE_IMAGE_F_SOA_ATTR) && db_entry && !ref_soa_ask) {
    zone_image_view_t cv;
    uint8_t cv_scope;
    zone_client_view(current_zone->image, cfg, zcfg, client_ip, ecs_trusted, edns.ecs_addr, edns.ecs_family, &cv, &cv_scope);
    if (zone_image_visible_soa(current_zone->image, &cv, NULL) == ZONE_IMAGE_NONE) {
      res[2] &= ~0x04;
      res[3] = (res[3] & 0xF0) | 5;
      add_ede(&edns, send_ede, 18, "Query refused: the zone is not served to this client");
      uint16_t roff = q_offset;
      uint16_t rar = 0;
      if (edns.present) {
        assemble_edns_opt(res, max_res_len, &roff, &rar, &edns, ext_rcode_out, is_tcp, cfg);
        res[10] = (uint8_t)(rar >> 8);
        res[11] = (uint8_t)(rar & 0xFF);
      }
      return roff;
    }
  }

  /* RFC 7314 §3: 権威を持つゾーンへの EXPIRE 付き問い合わせには、SOA EXPIRE (プライマリ)
   * または expire タイマーの残り (セカンダリ) を返す。権威が無い応答 (上の REFUSED) には
   * 付けない (§3.3)。値は本体に依存しないので wire キャッシュのヒット時も同じく付く。 */
  if (edns.present && edns.has_expire_query && db_entry && !is_badcookie) {
    edns.send_expire = true;
    edns.send_expire_value = zone_expire_option_value(db_entry, time(NULL));
  }

  uint16_t offset = q_offset, ancount = 0, nscount = 0, arcount = 0;

  if (is_badcookie) return build_badcookie_response(res, max_res_len, q_offset, &edns, ext_rcode_out, is_tcp, cfg);

  // UDP IXFR (RFC 1995 §4.2):
  // If client's SOA serial matches server's current serial (up-to-date), send single SOA response (NOERROR).
  // If update is needed (or diff required), set TC=1 and send current SOA to prompt client to retry over TCP.
  if (!is_tcp && qtype == 251) {
    uint32_t client_serial = 0;
    /* RFC 1995 §3: クライアントの版の SOA が Authority に無ければ FORMERR (TCP と同じ) */
    if (!ixfr_request_client_serial(req, req_len, q_offset, &client_serial))
      return dns_build_error_response(req, req_len, res, max_res_len, 1, 0, qdcount, &edns, is_tcp, cfg);

    const zone_image_t *zimg = current_zone->image;
    /* B8t-1: the SOA this client sees (the zone has one, checked above); the serial is the zone's, the same in all of them */
    uint32_t soa_rr = ZONE_IMAGE_NONE;
    uint32_t soa_ttl = 0;
    {
      zone_image_view_t iv;
      uint8_t iv_scope;
      zone_client_view(zimg, cfg, zcfg, client_ip, ecs_trusted, edns.ecs_addr, edns.ecs_family, &iv, &iv_scope);
      soa_rr = zone_image_visible_soa(zimg, &iv, &soa_ttl);
      if (ref_soa_ask) {
        soa_rr = zone_image_apex_soa(zimg);
        if (soa_rr != ZONE_IMAGE_NONE) soa_ttl = zone_image_rr_ttl(zimg, soa_rr);
      }
    }

    uint32_t current_serial = 0;
    zone_image_soa_t soa_nums;
    if (soa_rr != ZONE_IMAGE_NONE && zone_image_soa(zimg, soa_rr, NULL, 0, NULL, 0, &soa_nums) == 0) {
      current_serial = soa_nums.serial;
    } else {
      current_serial = atomic_load_explicit(&db_entry->serial, memory_order_relaxed);
    }

    /* R-15, RFC 1995 §2: 同じか新しい版 (RFC 1982) なら最新なので、TC を立てずに SOA 1件で答える */
    bool is_up_to_date = (client_serial == current_serial || serial_is_newer(client_serial, current_serial));
    /* provide-ixfr no does not change this answer: BIND 9.20 lib/ns/xfrout.c ns_xfr_start() answers an IXFR from a client that is up to date (and every
     * IXFR over UDP) with the one SOA before it looks at provide-ixfr.  A client that is behind is sent to TCP (TC), where send_axfr_response() gives it
     * the whole zone when provide-ixfr is no. */
    if (!is_up_to_date) {
      res[2] |= 0x02; // Set TC (Truncated) bit to prompt TCP retry
    }

    if (soa_rr != ZONE_IMAGE_NONE) {
      if (image_serialize_rr(zimg, soa_rr, res, body_max_len, &offset, comp_ctx, NULL, soa_ttl) >= 0) {
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

  if (ref_soa_ask && qtype == 6 && (current_zone->image->flags & ZONE_IMAGE_F_SOA_ATTR)) {
    const zone_image_t *zimg = current_zone->image;
    uint32_t soa_rr = zone_image_apex_soa(zimg);
    if (soa_rr != ZONE_IMAGE_NONE &&
        image_serialize_rr(zimg, soa_rr, res, body_max_len, &offset, comp_ctx, NULL, zone_image_rr_ttl(zimg, soa_rr)) >= 0)
      ancount = 1;
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

  /* 共有の応答キャッシュ (response_cache_init)。鍵の版 (rc_gen) は名前解決の前に読む:
   * 解決中に版が上がっても、古い版の鍵で入れた応答は二度と引かれない。 */
  /* minimal-responses of the client's view (lib/ns/query.c: client->view->minimalresponses), else options'; no-auth-recursive is no-auth for a
   * query with RD set and no for the others (ns_query_start()), so mr_mode is what the body is built with */
  int mr_mode = query_minimal_mode(cfg_for_ede, view, req);
  /* A zone shared with in-view, reached through a view that does not own it, and with NS / MX / SRV targets (current_zone->glue): the sibling
   * zones whose addresses go into the Additional section are looked up in the CLIENT's view (append_glue_records() 3., as BIND's query_getzonedb()
   * uses client->view), while the version, and so the cache entries and the sibling tracking of zone_glue_track_build(), belong to the owner view.
   * What this view's siblings would give is not in the key and nothing bumps the version when they change, so such answers are neither looked up
   * in nor stored into the cache (an entry stored for the owner view's clients would also lack, or carry, the other view's glue). */
  bool rc_view_dependent = current_zone && current_zone->glue && db_entry && view && !view_owns_entry(view, db_entry);
  uint64_t rc_tag = 0, rc_gen = 0;
  if (g_rcache && edns_safe_for_cache && !is_badcookie && opcode == 0 && qdcount == 1 && qclass == 1 && !rc_view_dependent &&
      current_zone && current_zone->rcache_ok && max_res_len >= 512 && q_offset < body_max_len) {
    rc_gen = zone_arena_data_generation(current_zone);
    /* The key has no view in it: the cache is shared by every view (a zone that two views share, in-view, has one set of entries) and the
     * client's ACLs were checked above, so a hit is only ever served to a client that may ask.  What can make the same question to the same zone
     * data answer differently is the response variant: here the minimal-responses mode the client's view and its RD bit select (the high bits of
     * the class slot, which is 1 here).  Two views with the same mode share entries; the generation of the configuration covers every other
     * setting. */
    rc_tag = rcache_tag(current_qname_lc, qtype, (uint16_t)(qclass | (mr_mode << 12)), rc_gen, cfg ? cfg->generation : 0);
    uint16_t c_an, c_ns, c_ar;
    int blen = rcache_lookup(rc_tag, rc_gen, qtype, res + q_offset, body_max_len - q_offset, &c_an, &c_ns, &c_ar);
    if (blen > 0) {
      uint16_t body_offset = (uint16_t)(q_offset + blen);
      uint16_t arcount = c_ar;
      res[2] |= 0x04; /* 入れるのは AA の応答だけ */
      if (edns.present) {
        assemble_edns_opt(res, max_res_len, &body_offset, &arcount, &edns, 0, is_tcp, cfg);
      }
      res[6] = (uint8_t)(c_an >> 8);
      res[7] = (uint8_t)(c_an & 0xFF);
      res[8] = (uint8_t)(c_ns >> 8);
      res[9] = (uint8_t)(c_ns & 0xFF);
      res[10] = (uint8_t)(arcount >> 8);
      res[11] = (uint8_t)(arcount & 0xFF);
      if (db_entry) atomic_fetch_add_explicit(&db_entry->observatory.wirecache_hits, 1, memory_order_relaxed);
      return body_offset;
    }
    if (db_entry) atomic_fetch_add_explicit(&db_entry->observatory.wirecache_misses, 1, memory_order_relaxed);
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
  t_resolve_crossed_zone = false;
  t_resolve_additional_cut = false;
  t_resolve_sibling_glue = false;
  t_resolve_alias_expanded = false;
  t_resolve_alias_failed = false;
  int minimal_mode = mr_mode;   /* minimal-responses of the client's view, no-auth-recursive resolved by the RD bit (above) */
  resolve_name(current_qname, qclass, qtypes, num_qtypes, &db_entry, &current_zone, res, body_max_len,
               &offset, comp_ctx, &ancount, &nscount, &arcount,
               minimal_mode,
               cfg_for_ede ? cfg_for_ede->minimal_any : false,
               cfg_for_ede ? cfg_for_ede->minimal_any_ttl : 86400,
               edns.dnssec_ok, view, &qtx_included, client_ip,
               cfg, ecs_trusted, edns.ecs_addr, edns.ecs_family,
               edns.ecs_source_prefix,
               &edns.ecs_scope_prefix);
  if (t_resolve_alias_failed && (res[3] & 0x0F) == 2) add_ede(&edns, send_ede, 22, "ALIAS target could not be resolved");   // 22: No Reachable Authority (RFC 8914)

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

  /* 応答キャッシュに入れる: NOERROR、AA、TC なしで answer があり、EDE の付かない応答
   * (ヒットした応答は UDP の 512 オクテットに入る大きさに限る)。別のゾーンへ移った応答と、Additional を打ち切った応答、兄弟ゾーンのグルーを使った応答 (C1) は入れない */
  if (rc_tag && !t_resolve_crossed_zone && !t_resolve_additional_cut && !t_resolve_sibling_glue && !t_resolve_alias_expanded && (res[3] & 0x0F) == 0 && (res[2] & 0x04) && !(res[2] & 0x02) && ancount > 0 &&
      edns.ede_count == 0 && offset > q_offset && offset <= UDP_DEFAULT_MAX_RES_LEN) {
    rcache_store(rc_tag, rc_gen, qtype, res + q_offset, (size_t)(offset - q_offset), ancount, nscount, arcount);
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
                      bool is_tcp, const rate_limit_config_t **out_rrl_cfg,
                      zone_db_snapshot_t *snap) {
  return process_dns_query_cap(req, req_len, res, max_res_len, 0, qname, qtype, client_ip, comp_ctx,
                               is_tcp, out_rrl_cfg, snap);
}

int process_dns_query_cap(const uint8_t *req, size_t req_len, uint8_t *res,
                          size_t max_res_len, size_t res_cap, const char *qname, uint16_t qtype,
                          const char *client_ip, compress_ctx_t *comp_ctx,
                          bool is_tcp, const rate_limit_config_t **out_rrl_cfg,
                          zone_db_snapshot_t *snap) {
  return process_dns_query_cap_routed(req, req_len, res, max_res_len, res_cap, qname, qtype, client_ip, comp_ctx,
                                      is_tcp, out_rrl_cfg, snap, NULL);
}

int process_dns_query_cap_routed(const uint8_t *req, size_t req_len, uint8_t *res,
                                 size_t max_res_len, size_t res_cap, const char *qname, uint16_t qtype,
                                 const char *client_ip, compress_ctx_t *comp_ctx,
                                 bool is_tcp, const rate_limit_config_t **out_rrl_cfg,
                                 zone_db_snapshot_t *snap, const query_route_t *route) {
  server_config_t *cfg = acquire_config_snapshot();
  zone_db_entry_t *matched_entry = NULL;
  int ret = process_dns_query_impl_cap_routed(req, req_len, res, max_res_len, res_cap, qname, qtype,
                                              client_ip, comp_ctx, is_tcp, out_rrl_cfg, snap, cfg, &matched_entry,
                                              route, NULL);
  release_config_snapshot(cfg);
  if (ret >= DNS_HEADER_SIZE && matched_entry) {
    uint8_t rcode = res[3] & 0x0F;
    uint16_t ancount = ((uint16_t)res[6] << 8) | (uint16_t)res[7];
    record_observatory_response(matched_entry, rcode, ancount);
  }
  return ret;
}

/* D1a: the answer of the worker for a query whose zone is in the directory and not in memory, when it cannot wait for it: the same view, ACL,
 * TSIG (RFC 8945 5.3) and rate limit handling as an answer from a zone, with SERVFAIL + EDE 14 as the content (route as for
 * process_dns_query_cap_routed(); elem: the directory element of the zone).
 * probe: the worker asks whether the query may be parked.  A query that the zone's allow-query (the full chain of the normal path: the zone's
 * own statement, the view's, options', allow-query-on, a TSIG key) refuses gets REFUSED + EDE 18 exactly as for a zone in memory, and so does
 * every other answer that is final (a malformed request, a TSIG error: FORMERR, NOTAUTH); the return value is that answer's length, and the
 * query neither parks nor asks for the zone.  DNS_NR_PERMITTED is returned (nothing written) for a query that may wait for the zone. */
int process_dns_not_ready_routed(const uint8_t *req, size_t req_len, uint8_t *res, size_t max_res_len, size_t res_cap, const char *qname,
                                 uint16_t qtype, const char *client_ip, compress_ctx_t *comp_ctx, bool is_tcp,
                                 const rate_limit_config_t **out_rrl_cfg, zone_db_snapshot_t *snap, const query_route_t *route,
                                 const zdir_elem_t *elem, bool probe) {
  server_config_t *cfg = acquire_config_snapshot();
  zone_db_entry_t *matched_entry = NULL;
  t_nr_probe = probe;
  int ret = process_dns_query_impl_cap_routed(req, req_len, res, max_res_len, res_cap, qname, qtype, client_ip, comp_ctx, is_tcp, out_rrl_cfg,
                                              snap, cfg, &matched_entry, route, elem);
  t_nr_probe = false;
  release_config_snapshot(cfg);
  return ret;
}

/* dnstap Message.query_zone (field 11) を埋める (O-03)。dnstap の送信スレッドが送る直前に
 * dnstap_set_zone_filler() 経由で呼ぶ (クエリの経路では呼ばない)。 */
void dnstap_fill_query_zone(dnstap_event_meta_t *meta, const uint8_t *wire, size_t wire_len) {
    meta->query_zone_len = 0;
    if (wire_len <= DNS_HEADER_SIZE || ((wire[4] << 8) | wire[5]) == 0) return;
    char qname[DNS_NAME_TEXT_SIZE];
    uint16_t qtype = 0, qclass = 0;
    size_t qend = 0;
    if (!parse_query_question_fast(wire, wire_len, qname, sizeof(qname), &qtype, &qclass, &qend)) return;
    char client_ip[INET6_ADDRSTRLEN] = "";
    if (meta->client_addr.ss_family == AF_INET)
        inet_ntop(AF_INET, &((const struct sockaddr_in *)&meta->client_addr)->sin_addr, client_ip, sizeof(client_ip));
    else if (meta->client_addr.ss_family == AF_INET6)
        inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)&meta->client_addr)->sin6_addr, client_ip, sizeof(client_ip));

    /* 応答を作ったときと同じく、クライアントのビューで QNAME を含む最も近いゾーンを引く。
     * 送信時点のスナップショットなので、その間にリロードがあれば新しいゾーン構成で決まる。 */
    char zone[DNS_NAME_TEXT_SIZE];
    bool found = false;
    rcu_aux_read_lock();
    zone_db_snapshot_t *snap = acquire_zone_snapshot();
    /* the view as the engine chose it, with the TSIG of a query for a view whose match-clients has a `key`; a response is matched as an unsigned
     * message (its TSIG is checked against the query's MAC, which is not at hand) */
    tsig_request_t dtsig;
    bool dtsig_done;
    server_config_t *dcfg = acquire_config_snapshot();
    view_snapshot_t *view = snap ? select_view_req(snap, dcfg, client_ip, (wire[2] & 0x80) ? NULL : wire, wire_len, &dtsig, &dtsig_done) : NULL;
    release_config_snapshot(dcfg);
    zone_db_entry_t *entry = view ? find_zone_in_view(view, qname) : NULL;
    if (entry) {
        strlcpy(zone, entry->domain, sizeof(zone));
        found = true;
    }
    rcu_aux_read_unlock();
    if (!found) return;
    if (zone[0] == '\0' || strcmp(zone, ".") == 0) {
        meta->query_zone[0] = 0; /* ルートゾーン */
        meta->query_zone_len = 1;
        return;
    }
    long n = write_uncompressed_name(meta->query_zone, 0, sizeof(meta->query_zone), zone);
    if (n > 0) meta->query_zone_len = (uint16_t)n;
}

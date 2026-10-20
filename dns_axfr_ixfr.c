#define OPENSSL_SUPPRESS_DEPRECATED 1
#include "dns_axfr_ixfr.h"
#include "dns_wire.h"
#include "dns_zone_parser.h"
#include "dns_zone_image.h"
#include "dns_config_parser.h"
#include "dns_utils.h"
#include "dns_catalog_zone.h"
#include "dns_dnstap.h"
#include "dns_edns_ecs.h"
#include "dns_priv_sandbox.h"
#include "dns_dynamic_update.h"
#include "dns_tsig_acl.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

void free_ixfr_txn(ixfr_txn_t *txn) {
  if (!txn) return;
  zone_arena_destroy(&txn->arena);
  if (txn->deleted) free(txn->deleted);
  if (txn->added) free(txn->added);
  free(txn);
}

bool wait_for_active_axfr(zone_db_entry_t *entry, int timeout_ms) {
  if (!entry) return true;
  int retries = 0;
  useconds_t sleep_time = 1;
  struct timespec start, now;
  clock_gettime(CLOCK_MONOTONIC, &start);

  while (atomic_load_explicit(&entry->active_axfr, memory_order_acquire) > 0) {
    if (timeout_ms > 0) {
      clock_gettime(CLOCK_MONOTONIC, &now);
      int64_t elapsed_ms = (int64_t)(now.tv_sec - start.tv_sec) * 1000 +
                           (int64_t)(now.tv_nsec - start.tv_nsec) / 1000000;
      if (elapsed_ms >= timeout_ms) {
        syslog(LOG_WARNING, "[AXFR] wait_for_active_axfr timed out after %d ms for zone '%s'",
               timeout_ms, entry->domain);
        return false;
      }
    }
    rcu_exponential_backoff(&retries, &sleep_time);
  }
  return true;
}

/* ---- IXFR difference (S5 B-2): two images are compared; the old builder no longer exists ----
 * An RR of one version is "in" the other when the other has an RR with the same owner (case-insensitive), type, class,
 * TTL, tinydns time stamp / location, tags and RDATA (RFC 2136 §1.1.1: equal RDATA is the same RR; names compare as
 * RFC 4034 §6.2 canonical form, the way compare_records() did on builder records). */
static bool ixfr_ext_equal(const zone_image_ext_t *a, const zone_image_ext_t *b, const zone_image_t *ia,
                           const zone_image_t *ib) {
  if (!a && !b) return true;
  zone_image_ext_t none;
  memset(&none, 0, sizeof(none));
  if (!a) a = &none;
  if (!b) b = &none;
  if (a->ttd != b->ttd || ((a->flags ^ b->flags) & ZONE_IMAGE_EXT_COUNTDOWN) || a->loc[0] != b->loc[0] ||
      a->loc[1] != b->loc[1])
    return false;
  const char *ea = zone_image_str(ia, a->ecs_tag_off), *eb = zone_image_str(ib, b->ecs_tag_off);
  const char *la = zone_image_str(ia, a->loc_tag_off), *lb = zone_image_str(ib, b->loc_tag_off);
  if ((ea == NULL) != (eb == NULL) || (ea && strcasecmp(ea, eb) != 0)) return false;
  if ((la == NULL) != (lb == NULL) || (la && strcasecmp(la, lb) != 0)) return false;
  return true;
}

static bool ixfr_rdata_equal(const zone_image_t *ia, uint32_t a, const zone_image_t *ib, uint32_t b) {
  uint16_t la = zone_image_rr_rdlen(ia, a), lb = zone_image_rr_rdlen(ib, b);
  if (la != lb) return false;
  if (la == 0) return true;
  const uint8_t *pa = zone_image_rr_rdata(ia, a), *pb = zone_image_rr_rdata(ib, b);
  if (memcmp(pa, pb, la) == 0) return true;
  /* the stored RDATA is uncompressed, so a difference can only be the case of a domain name; only the types with
   * names in their RDATA can be equal in canonical form, and then only if the octets agree when case is folded */
  uint16_t type = zone_image_rr_type(ia, a);
  if (!dns_rdata_name_layout(type) && !(zone_image_rrs(ia)[a].flags & ZONE_IMAGE_RR_RAW)) return false;
  for (uint16_t i = 0; i < la; i++) {
    uint8_t x = pa[i], y = pb[i];
    if (x >= 'A' && x <= 'Z') x |= 0x20;
    if (y >= 'A' && y <= 'Z') y |= 0x20;
    if (x != y) return false;
  }
  /* exact answer through the same comparison the builder records used */
  zone_arena_t scratch;
  zone_arena_init(&scratch);
  dns_record_t ra, rb;
  bool same = zone_image_rr_to_record(ia, a, &scratch, &ra) == 0 && zone_image_rr_to_record(ib, b, &scratch, &rb) == 0 &&
              compare_records(&ra, &rb, true);
  zone_arena_destroy(&scratch);
  return same;
}

/* Is RR `rr` of image `img` also in `other`? */
static bool ixfr_rr_in(const zone_image_t *img, uint32_t rr, const zone_image_t *other) {
  uint32_t id = zone_image_find_name(other, zone_image_name_text(img, zone_image_rr_name(img, rr)));
  if (id == ZONE_IMAGE_NONE) return false;
  uint16_t type = zone_image_rr_type(img, rr);
  const zone_image_ext_t *ext = zone_image_rr_ext(img, rr);
  for (uint32_t k = zone_image_rrset_next(other, id, type, zone_image_name_first_rr(other, id)); k != ZONE_IMAGE_NONE;
       k = zone_image_rrset_next(other, id, type, k + 1)) {
    if (zone_image_rr_class(other, k) != zone_image_rr_class(img, rr) ||
        zone_image_rr_ttl(other, k) != zone_image_rr_ttl(img, rr))
      continue;
    if (!ixfr_ext_equal(ext, zone_image_rr_ext(other, k), img, other)) continue;
    if (ixfr_rdata_equal(img, rr, other, k)) return true;
  }
  return false;
}

static bool ixfr_apex_serial(const zone_image_t *img, uint32_t *serial) {
  uint32_t rr = zone_image_apex_soa(img);
  zone_image_soa_t nums;
  if (rr == ZONE_IMAGE_NONE || zone_image_soa(img, rr, NULL, 0, NULL, 0, &nums) != 0) return false;
  *serial = nums.serial;
  return true;
}

#define IXFR_MAX_DELTA 10000

/* The RRs of `img` (in file order) that are not in `other`, up to IXFR_MAX_DELTA + 1 - *budget_used... returns the
 * count, or (size_t)-1 when it does not fit in `cap`. */
static size_t ixfr_collect(const zone_image_t *img, const zone_image_t *other, uint32_t *out, size_t cap) {
  size_t n = 0;
  for (uint32_t seq = 0; seq < img->n_rrs; seq++) {
    uint32_t rr = zone_image_seq_rr(img, seq);
    if (ixfr_rr_in(img, rr, other)) continue;
    if (n >= cap) return (size_t)-1;
    out[n++] = rr;
  }
  return n;
}

static int ixfr_fill(const zone_image_t *img, const uint32_t *rrs, size_t n, dns_record_t *out, zone_arena_t *arena) {
  for (size_t i = 0; i < n; i++)
    if (zone_image_rr_to_record(img, rrs[i], arena, &out[i]) != 0) return -1;
  return 0;
}

static void ixfr_txn_release(ixfr_txn_t *txn) {
  if (txn && atomic_fetch_sub_explicit(&txn->ref_count, 1, memory_order_acq_rel) == 1) free_ixfr_txn(txn);
}

/* Change the ring to `newcap` slots (h->lock held), keeping the newest diffs in order (oldest first, from slot 0). */
static int ixfr_ring_resize(ixfr_history_t *h, int newcap) {
  ixfr_txn_t **ring = NULL;
  if (newcap > 0) {
    ring = calloc((size_t)newcap, sizeof(*ring));
    if (!ring) return -1;
  }
  int keep = h->count < newcap ? h->count : newcap;
  for (int i = 0; i < h->count; i++) {
    ixfr_txn_t *t = h->entries[(h->head + h->cap - h->count + i) % h->cap];
    if (i >= h->count - keep) ring[i - (h->count - keep)] = t;
    else ixfr_txn_release(t); /* the oldest ones go */
  }
  free(h->entries);
  h->entries = ring;
  h->cap = (uint8_t)newcap;
  h->count = (uint8_t)keep;
  h->head = (uint8_t)(newcap > 0 ? keep % newcap : 0);
  return 0;
}

void ixfr_history_set_depth(zone_db_entry_t *entry, int depth) {
  if (depth < 0) depth = 0;
  if (depth > MAX_IXFR_HISTORY) depth = MAX_IXFR_HISTORY;
  ixfr_history_t *h = &entry->ixfr_history;
  pthread_mutex_lock(&h->lock);
  h->depth_p1 = (uint8_t)(depth + 1);
  /* a lower depth drops the oldest diffs now; a higher one grows the ring at the next stored diff */
  if (h->entries && depth < h->cap) (void)ixfr_ring_resize(h, depth);
  pthread_mutex_unlock(&h->lock);
}

void ixfr_history_clear(ixfr_history_t *h) {
  for (int i = 0; i < h->cap && h->entries; i++)
    if (h->entries[i]) free_ixfr_txn(h->entries[i]);
  free(h->entries);
  h->entries = NULL;
  h->cap = h->head = h->count = 0;
}

/* Compare the published image of old_ver with the new one and keep the difference in the IXFR history of `entry`
 * (RFC 1995 §4: deletions and additions per version). Does nothing when the zone keeps no history (ixfr-history 0), a
 * serial is missing or not newer, or when the difference is larger than IXFR_MAX_DELTA RRs. */
void compute_ixfr_diff(zone_db_entry_t *entry, const zone_version_t *old_ver, const zone_version_t *new_ver) {
  const zone_image_t *oi = old_ver ? old_ver->image : NULL, *ni = new_ver ? new_ver->image : NULL;
  if (!oi || !ni) return;
  pthread_mutex_lock(&entry->ixfr_history.lock);
  int depth = ixfr_history_depth(&entry->ixfr_history);
  pthread_mutex_unlock(&entry->ixfr_history.lock);
  if (depth == 0) return;
  uint32_t old_serial = 0, new_serial = 0;
  (void)ixfr_apex_serial(oi, &old_serial);
  (void)ixfr_apex_serial(ni, &new_serial);
  if (old_serial == 0 || new_serial == 0) return;
  if ((int32_t)(new_serial - old_serial) <= 0) return;

  uint32_t *del_rr = malloc((IXFR_MAX_DELTA + 1) * sizeof(uint32_t));
  uint32_t *add_rr = malloc((IXFR_MAX_DELTA + 1) * sizeof(uint32_t));
  ixfr_txn_t *txn = NULL;
  if (!del_rr || !add_rr) goto out;
  size_t del_count = ixfr_collect(oi, ni, del_rr, IXFR_MAX_DELTA);
  if (del_count == (size_t)-1) goto out;
  size_t add_count = ixfr_collect(ni, oi, add_rr, IXFR_MAX_DELTA - del_count);
  if (add_count == (size_t)-1) goto out;

  txn = calloc(1, sizeof(ixfr_txn_t));
  if (!txn) goto out;
  zone_arena_init(&txn->arena);
  /* S4: a small difference does not get a 64 KiB first pool */
  txn->arena.first_pool_cap = ((del_count + add_count) * 512 + 1024) < 64 * 1024 ? (del_count + add_count) * 512 + 1024 : 64 * 1024;
  /* the records live in the transaction's own arena: the images are freed with their versions */
  if (del_count > 0) txn->deleted = calloc(del_count, sizeof(dns_record_t));
  if (add_count > 0) txn->added = calloc(add_count, sizeof(dns_record_t));
  if ((del_count > 0 && !txn->deleted) || (add_count > 0 && !txn->added) ||
      ixfr_fill(oi, del_rr, del_count, txn->deleted, &txn->arena) != 0 ||
      ixfr_fill(ni, add_rr, add_count, txn->added, &txn->arena) != 0) {
    syslog(LOG_WARNING, "[IXFR] zone '%s': could not record the difference between serial %u and %u", entry->domain,
           old_serial, new_serial);
    free_ixfr_txn(txn);
    txn = NULL;
    goto out;
  }
  txn->old_serial = old_serial;
  txn->new_serial = new_serial;
  txn->deleted_count = (int)del_count;
  txn->added_count = (int)add_count;
  atomic_init(&txn->ref_count, 1);

  ixfr_history_t *h = &entry->ixfr_history;
  pthread_mutex_lock(&h->lock);
  depth = ixfr_history_depth(h); /* may have changed while the diff was computed */
  /* the ring is made on the first diff, with the configured size; a raised depth grows it here */
  if (depth > 0 && (!h->entries || h->cap < depth) && ixfr_ring_resize(h, depth) != 0) depth = 0;
  if (depth == 0) {
    pthread_mutex_unlock(&h->lock);
    free_ixfr_txn(txn);
    goto out;
  }
  if (h->count == h->cap) {
    ixfr_txn_release(h->entries[h->head]);
  } else {
    h->count++;
  }
  h->entries[h->head] = txn;
  h->head = (uint8_t)((h->head + 1) % h->cap);
  pthread_mutex_unlock(&h->lock);
out:
  free(del_rr);
  free(add_rr);
}

static const char *xfr_rcode_name(unsigned rcode) {
  static const char *const names[] = {"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED",
                                      "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE"};
  return rcode < sizeof(names) / sizeof(names[0]) ? names[rcode] : "RCODE";
}

int xfr_check_response_header(const uint8_t *msg, size_t msg_len, axfr_session_t *session, const char *domain) {
  const char *qt = session->query_type == 251 ? "IXFR" : "AXFR";
  if (msg_len < DNS_HEADER_SIZE) {
    syslog(LOG_WARNING, "[AXFR] zone '%s': rejecting %s response: %zu bytes, shorter than a DNS header",
           domain, qt, msg_len);
    return -1;
  }
  /* RFC 5936 §2.2.1: ID は全メッセージで要求の ID、QR=1、OPCODE=0。違うものは別の応答として捨てる
   * (Note a)。1本の TCP 接続で要求は1つだけなので、転送を失敗にする。 */
  uint16_t id = (uint16_t)((msg[0] << 8) | msg[1]);
  if (id != session->query_id) {
    syslog(LOG_WARNING, "[AXFR] zone '%s': rejecting %s response: ID %u does not match the request ID %u",
           domain, qt, id, session->query_id);
    return -1;
  }
  if ((msg[2] & 0x80) == 0 || ((msg[2] >> 3) & 0x0F) != 0) {
    syslog(LOG_WARNING, "[AXFR] zone '%s': rejecting %s response: QR=%u OPCODE=%u (expected QR=1 OPCODE=0)",
           domain, qt, (unsigned)(msg[2] >> 7), (unsigned)((msg[2] >> 3) & 0x0F));
    return -1;
  }
  uint16_t qdcount = (uint16_t)((msg[4] << 8) | msg[5]);
  bool first = !session->got_first_msg;
  session->got_first_msg = true;
  /* RFC 5936 §2.2.1, §2.2.2: 最初のメッセージとエラー応答は QDCOUNT=1 で要求の質問を写す。
   * 後続のメッセージは 0 か 1。 */
  unsigned rcode = msg[3] & 0x0F;
  if (qdcount > 1 || (qdcount == 0 && (first || rcode != 0))) {
    syslog(LOG_WARNING, "[AXFR] zone '%s': rejecting %s response: QDCOUNT %u", domain, qt, qdcount);
    return -1;
  }
  if (qdcount == 1) {
    char qname[DNS_NAME_TEXT_SIZE];
    size_t q_end;
    if (expand_wire_name_to_buffer(msg, msg_len, DNS_HEADER_SIZE, &q_end, qname, sizeof(qname)) < 0 ||
        q_end + 4 > msg_len) {
      syslog(LOG_WARNING, "[AXFR] zone '%s': rejecting %s response: malformed question section", domain, qt);
      return -1;
    }
    uint16_t rtype = (uint16_t)((msg[q_end] << 8) | msg[q_end + 1]);
    uint16_t rclass = (uint16_t)((msg[q_end + 2] << 8) | msg[q_end + 3]);
    if (!domain_names_match_ci(qname, domain) || rtype != session->query_type || rclass != 1) {
      syslog(LOG_WARNING, "[AXFR] zone '%s': rejecting %s response: question '%s' type %u class %u does not "
             "match the request", domain, qt, qname, rtype, rclass);
      return -1;
    }
  }
  /* RFC 5936 §2.2.1 Note e): エラーの RCODE ならその場で転送を終える (タイムアウトを待たない) */
  if (rcode != 0) {
    session->rcode = (uint8_t)rcode;
    syslog(LOG_WARNING, "[AXFR] zone '%s': primary answered the %s request with %s (%u)",
           domain, qt, xfr_rcode_name(rcode), rcode);
    return 1;
  }
  return 0;
}

int parse_xfr_packet(const uint8_t *packet, size_t packet_len,
                     zone_arena_t *standby, const zone_version_t *active,
                     axfr_session_t *session, const char *domain) {
  /* 拒否する経路では、運用者が原因を探せるよう必ずゾーン名と理由をログに出す (R-27) */
  if (packet_len < DNS_HEADER_SIZE) {
    syslog(LOG_WARNING, "[AXFR] zone '%s': rejecting transfer message: %zu bytes, shorter than a DNS header",
           domain, packet_len);
    return -1;
  }
  uint16_t qdcount = (packet[4] << 8) | packet[5],
           ancount = (packet[6] << 8) | packet[7];
  size_t offset = DNS_HEADER_SIZE;
  // RFC 5936 §2.2: Even on subsequent messages (session->soa_count > 0),
  // master implementations may include the question section (QDCOUNT > 0).
  // Safely skip any question records present in the packet.
  for (int i = 0; i < qdcount; i++) {
    size_t next_offset;
    if (skip_wire_name(packet, packet_len, offset, &next_offset) != 0 || next_offset + 4 > packet_len) {
      syslog(LOG_WARNING, "[AXFR] zone '%s': rejecting transfer message: malformed question section", domain);
      return -1;
    }
    offset = next_offset + 4;
  }

  // Check EDNS OPT Option 65153 (and RFC 7314 EXPIRE) on the initial packet
  if (session->soa_count == 0) {
    uint16_t nscount = (packet[8] << 8) | packet[9];
    uint16_t arcount = (packet[10] << 8) | packet[11];
    if (arcount > 0) {
      edns_info_t edns = {0};
      if (parse_edns_opt(packet, packet_len, qdcount, ancount, nscount, arcount, &edns) == 0) {
        if (edns.has_expire_value) {
          session->has_expire = true;
          session->expire = edns.expire_value;
        }
        if (edns.has_karidns_ext && edns.karidns_ext_version == KARIDNS_EXT_VERSION) {
          uint32_t exp_hash = calc_fnv1a_str(domain);
          if (edns.karidns_ext_hash == exp_hash) {
            session->is_extended_mode = true;
          }
        }
      }
    }
  }

  for (int i = 0; i < ancount; i++) {
    if (standby->count >= standby->records_cap) {
      size_t new_cap =
          standby->records_cap == 0 ? 16 : standby->records_cap * 2;
      dns_record_t *new_records = NULL;
      if (new_cap <= SIZE_MAX / sizeof(dns_record_t))
        new_records = realloc(standby->records, new_cap * sizeof(dns_record_t));
      if (!new_records) {
        syslog(LOG_ERR, "[AXFR] zone '%s': out of memory storing %zu records", domain, standby->count);
        return -1;
      }
      memset(new_records + standby->records_cap, 0,
             (new_cap - standby->records_cap) * sizeof(dns_record_t));
      standby->records = new_records;
      standby->records_cap = new_cap;
    }
    dns_record_t *rec = &standby->records[standby->count];
    memset(rec, 0, sizeof(*rec));
    uint16_t type;
    if (parse_resource_record(packet, packet_len, &offset, standby, rec,
                              &type) != 0) {
      syslog(LOG_WARNING, "[AXFR] zone '%s': rejecting transfer message: malformed answer RR %d of %u",
             domain, i + 1, ancount);
      return -1;
    }
    standby->count++;

    // KariDNS Extended AXFR record interception:
    if (rec->class_val == DNS_CLASS_KARIDNS_EXT) {
      if (type == DNS_TYPE_KARIDNS_LOC_STATE) {
        standby->count--;
        if (rec->generic_data && rec->generic_len > 0) {
          size_t copy_len = rec->generic_len < sizeof(session->current_loc_tag) - 1 ? rec->generic_len : sizeof(session->current_loc_tag) - 1;
          memcpy(session->current_loc_tag, rec->generic_data, copy_len);
          session->current_loc_tag[copy_len] = '\0';
          session->has_current_loc_tag = true;
        } else {
          session->current_loc_tag[0] = '\0';
          session->has_current_loc_tag = false;
        }
        continue;
      } else if (type == DNS_TYPE_KARIDNS_ECS_STATE) {
        standby->count--;
        if (rec->generic_data && rec->generic_len > 0) {
          size_t copy_len = rec->generic_len < sizeof(session->current_ecs_tag) - 1 ? rec->generic_len : sizeof(session->current_ecs_tag) - 1;
          memcpy(session->current_ecs_tag, rec->generic_data, copy_len);
          session->current_ecs_tag[copy_len] = '\0';
          session->has_current_ecs_tag = true;
        } else {
          session->current_ecs_tag[0] = '\0';
          session->has_current_ecs_tag = false;
        }
        continue;
      } else if (type == DNS_TYPE_KARIDNS_LOC_TAGDEF) {
        standby->count--;
        unpack_tag_def_rdata(rec->generic_data, rec->generic_len, &standby->bind_location_tags, &standby->bind_location_tag_count);
        continue;
      } else if (type == DNS_TYPE_KARIDNS_ECS_TAGDEF) {
        standby->count--;
        unpack_tag_def_rdata(rec->generic_data, rec->generic_len, &standby->bind_ecs_tags, &standby->bind_ecs_tag_count);
        continue;
      } else if (type == DNS_TYPE_KARIDNS_ECS_TRUSTED) {
        standby->count--;
        unpack_trusted_resolvers_rdata(rec->generic_data, rec->generic_len, &standby->bind_ecs_trusted_resolvers, &standby->bind_ecs_trusted_resolver_count);
        if (standby->bind_ecs_trusted_resolvers_parsed) {
          free(standby->bind_ecs_trusted_resolvers_parsed);
          standby->bind_ecs_trusted_resolvers_parsed = NULL;
        }
        if (standby->bind_ecs_trusted_resolver_count > 0 && standby->bind_ecs_trusted_resolvers) {
          standby->bind_ecs_trusted_resolvers_parsed = acl_list_parse(standby->bind_ecs_trusted_resolvers, standby->bind_ecs_trusted_resolver_count);
        }
        continue;
      } else if (type == DNS_TYPE_KARIDNS_TINYDNS_LOCDEF) {
        standby->count--;
        standby->is_tinydns_format = true;
        unpack_tinydns_loc_rdata(rec->generic_data, rec->generic_len, &standby->locations, &standby->location_count);
        continue;
      } else if (type == DNS_TYPE_KARIDNS_TINYDNS_WRAP) {
        standby->is_tinydns_format = true;
        if (rec->generic_data && rec->generic_len >= 21) {
          uint16_t orig_type = (rec->generic_data[0] << 8) | rec->generic_data[1];
          uint16_t orig_class = (rec->generic_data[2] << 8) | rec->generic_data[3];
          uint32_t orig_ttl = ((uint32_t)rec->generic_data[4] << 24) | ((uint32_t)rec->generic_data[5] << 16) | ((uint32_t)rec->generic_data[6] << 8) | rec->generic_data[7];
          char loc[2] = { (char)rec->generic_data[8], (char)rec->generic_data[9] };
          uint64_t ttd = 0;
          for (int b = 0; b < 8; b++) {
            ttd = (ttd << 8) | rec->generic_data[10 + b];
          }
          uint8_t flags = rec->generic_data[18];
          uint16_t orig_rdlen = (rec->generic_data[19] << 8) | rec->generic_data[20];
          if (21 + orig_rdlen <= rec->generic_len) {
            uint8_t fake_wire[4096];
            size_t fake_len = 0;
            bool reconstructed = false;
            const char *d = rec->name;
            while (*d) {
              const char *dot = strchr_unescaped(d, '.');
              size_t len = dot ? (size_t)(dot - d) : strlen(d);
              if (len > 63) len = 63;
              if (fake_len + len + 2 > sizeof(fake_wire) - 100) break;
              fake_wire[fake_len++] = (uint8_t)len;
              memcpy(&fake_wire[fake_len], d, len);
              fake_len += len;
              if (!dot) break;
              d = dot + 1;
            }
            fake_wire[fake_len++] = 0;
            fake_wire[fake_len++] = (orig_type >> 8) & 0xFF;
            fake_wire[fake_len++] = orig_type & 0xFF;
            fake_wire[fake_len++] = (orig_class >> 8) & 0xFF;
            fake_wire[fake_len++] = orig_class & 0xFF;
            fake_wire[fake_len++] = (orig_ttl >> 24) & 0xFF;
            fake_wire[fake_len++] = (orig_ttl >> 16) & 0xFF;
            fake_wire[fake_len++] = (orig_ttl >> 8) & 0xFF;
            fake_wire[fake_len++] = orig_ttl & 0xFF;
            fake_wire[fake_len++] = (orig_rdlen >> 8) & 0xFF;
            fake_wire[fake_len++] = orig_rdlen & 0xFF;
            /* SECURITY FIX: orig_rdlen comes from the wrapped rdata sent by the
             * AXFR/IXFR peer and can be up to 65535, far larger than the fixed
             * fake_wire[4096] stack buffer. Previously this was copied
             * unconditionally, allowing a malicious/compromised zone-transfer
             * source to overflow the stack. Verify it fits before copying, and
             * fall back to the existing synthetic-record path otherwise. */
            if (orig_rdlen > 0 && fake_len + (size_t)orig_rdlen <= sizeof(fake_wire)) {
              memcpy(&fake_wire[fake_len], &rec->generic_data[21], orig_rdlen);
              fake_len += orig_rdlen;
            } else if (orig_rdlen > 0) {
              fake_len = 0; /* force fallback below; do not attempt to parse */
            }
            size_t fake_off = 0;
            uint16_t parsed_t;
            dns_record_t unwrapped;
            memset(&unwrapped, 0, sizeof(unwrapped));
            if (fake_len > 0 &&
                parse_resource_record(fake_wire, fake_len, &fake_off, standby, &unwrapped, &parsed_t) == 0) {
              *rec = unwrapped;
              type = parsed_t;
              reconstructed = true;
            }
            if (!reconstructed) {
              rec->generic_data = NULL;
              rec->generic_len = 0;
              rec->type_code = orig_type;
              rec->class_val = orig_class;
              rec->ttl_value = orig_ttl > 0x7FFFFFFFu ? 0x7FFFFFFFu : orig_ttl; // RFC 8767 §4 (O-14)
              rec->type = (char *)get_type_str(orig_type, standby);
              rec->class_str = (orig_class == 1) ? "IN" : "CH";
              char *ttl_buf = arena_alloc(standby, 16);
              if (ttl_buf) {
                snprintf(ttl_buf, 16, "%u", rec->ttl_value);
                rec->ttl = ttl_buf;
              }
              type = orig_type;
            }
          }
          rec->tinydns_loc[0] = loc[0];
          rec->tinydns_loc[1] = loc[1];
          rec->tinydns_ttd = ttd;
          rec->tinydns_ttl_countdown = (flags & 1) ? true : false;
        }
      }
    }

    /* RFC 1034 §4.2 / RFC 5936 §2.2: ゾーンは apex とその下のデータ。ゾーン外の RR は
     * 1件で転送全体を捨てず、格納せずに読み飛ばす (BIND も同様に無視する)。
     * SOA は転送の始まりと終わりを示すので、ゾーン外の SOA はプロトコル違反として拒否する。*/
    if (!domain_name_is_at_or_below(rec->name, domain)) {
      const char *owner = rec->name ? rec->name : "";
      if (type == 6) {
        syslog(LOG_WARNING, "[AXFR] zone '%s': rejecting transfer: SOA with out-of-zone owner '%s'",
               domain, owner);
        return -1;
      }
      standby->count--;
      if (session->out_of_zone_skipped++ < 10) {
        syslog(LOG_WARNING, "[AXFR] zone '%s': ignoring out-of-zone record '%s' type %u in transfer",
               domain, owner, (unsigned)type);
      }
      continue;
    }
    if (session->has_current_loc_tag && session->current_loc_tag[0] != '\0') {
      rec->bind_location_tag = arena_strdup(standby, session->current_loc_tag);
    }
    if (session->has_current_ecs_tag && session->current_ecs_tag[0] != '\0') {
      rec->ecs_subnet_tag = arena_strdup(standby, session->current_ecs_tag);
    }
    if (type == 6) {
      session->soa_count++;
      uint32_t current_serial = strtoul(rec->rdata[2], NULL, 10);
      if (session->soa_count == 1) {
        strncpy(session->initial_soa_name, rec->name,
                sizeof(session->initial_soa_name) - 1);
        session->initial_soa_serial = current_serial;
        if (session->is_ixfr && ancount == 1 &&
            current_serial == session->client_serial) {
          session->is_finished = true;
          standby->count = 0;
          return 0;
        }

        if (session->client_serial != 0) {
          if (current_serial == session->client_serial) {
            session->is_finished = true;
            standby->count = 0;
            return 0;
          }
          if (!serial_is_newer(current_serial, session->client_serial)) {
            syslog(LOG_WARNING,
                   "[AXFR] Rejecting transfer for zone '%s': received serial %u is not newer "
                   "than current serial %u (possible rollback or spoofed master)",
                   domain, current_serial, session->client_serial);
            return -1;
          }
        }
      } else if (session->soa_count == 2 && session->is_ixfr) {
        /* the IXFR is applied to the version we serve now: rebuild its builder from the published image (S5 B-2) */
        if (thaw_zone_arena(active, standby) != 0) {
          syslog(LOG_ERR, "[AXFR] zone '%s': cannot rebuild the current version of the zone to apply the IXFR", domain);
          return -1;
        }
        session->is_deleting = true;
      } else if (session->is_ixfr && session->is_deleting) {
        session->is_deleting = false;
        for (size_t k = 0; k < standby->count - 1; k++) {
          if (standby->records[k].type_code == 6 &&
              domain_names_match_ci(standby->records[k].name, domain)) {
            standby->records[k] = standby->records[standby->count - 1];
            standby->count--;
            break;
          }
        }
      } else if (session->is_ixfr && !session->is_deleting) {
        if (current_serial == session->initial_soa_serial) {
          session->is_finished = true;
          standby->count--;
        } else {
          session->is_deleting = true;
          standby->count--;
        }
      } else {
        if (domain_names_match_ci(session->initial_soa_name, rec->name) &&
            session->initial_soa_serial == current_serial) {
          session->is_finished = true;
          standby->count--;
          if (i != ancount - 1) session->trailing_rrs = true; /* RFC 5936 §2.2: the final SOA is the last RR (the database loader checks it) */
        }
      }
    } else {
      if (session->soa_count == 1 && session->is_ixfr)
        session->is_ixfr = false;
      if (session->is_ixfr && session->is_deleting) {
        standby->count--;
        for (size_t k = 0; k < standby->count; k++) {
          if (compare_records(&standby->records[k], rec, true)) {
            standby->records[k] = standby->records[--standby->count];
            break;
          }
        }
      }
    }
  }
  return 0;
}

/* RFC 7314 §4: 転送・更新確認の結果から expire タイマーの期限 (絶対時刻) を決める。
 *   - ゾーンを転送した (transferred): EXPIRE があればその値で、無ければ SOA EXPIRE で初期化
 *   - 最新だった (IXFR で serial 一致): EXPIRE があれば現在のタイマーとの大きい方。
 *     無ければ従来どおり SOA EXPIRE で数え直す (EXPIRE 非対応のプライマリ)
 *   いずれも SOA EXPIRE を上限とする。戻り値 0 は「last_successful_transfer + SOA EXPIRE」。 */
time_t xfr_expire_deadline(bool transferred, bool has_expire, uint32_t expire_opt,
                                       uint32_t soa_expire, time_t cur_deadline, time_t now) {
  if (!has_expire) return 0;
  uint32_t v = (soa_expire > 0 && expire_opt > soa_expire) ? soa_expire : expire_opt;
  time_t deadline = now + (time_t)v;
  if (!transferred && cur_deadline > deadline) deadline = cur_deadline;
  if (soa_expire > 0 && deadline > now + (time_t)soa_expire) deadline = now + (time_t)soa_expire;
  return deadline;
}

/* 組み上がったゾーン (builder) を新しい版として公開する。AXFR/IXFR の受信 (handle_axfr_event) と、
 * 取り込み側が同じ手順を使う (ずれないようにここに 1 つだけ置く)。
 * 手順: 配列の縮小 -> build_zone_index(RRset の TTL をそろえる) -> zone_image_freeze -> 作り手の解放 -> 新しい版 ->
 *       グルーの追跡と応答キャッシュ (設定とスナップショットは読み取り区間の中で読む) -> compute_ixfr_diff -> zone_publish。
 * 呼ぶ側の約束:
 *   - entry->writer_lock を持って呼ぶ (呼んだ後も持ったまま。解放は呼ぶ側)。wait_for_active_axfr() も呼ぶ側が済ませる。
 *   - 書けない RR は zone_drop_unencodable_logged() で呼ぶ前に除いておく (SOA の取り出しがその後に要るため呼ぶ側に置く)。
 *   - serial / refresh / retry / expire / next_check / expire_at / last_successful_transfer と、統計 (observatory)、
 *     notify_request_send() は呼ぶ側が行う。
 * 戻り値 0: builder の image は公開した版に移り (builder に残るのはレコード等の解放済みの殻)、entry の公開が済んでいる。
 * 戻り値 -1: 何も公開していない (ログ済み。what は "after %s" に入る)。image はここで解放しないので builder に残る。
 * どちらの場合も builder は呼ぶ側が zone_arena_destroy() する (二重に呼んでも安全)。*/
int zone_install_builder(zone_db_entry_t *entry, zone_arena_t *builder, const char *what) {
  zone_version_t *cur_active = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);

  zone_arena_shrink_records(builder);
  if (build_zone_index(builder, true) != 0) {
    syslog(LOG_ERR, "[Zone] Memory allocation failed while building index after %s for '%s'", what, entry->domain);
    return -1;
  }

  /* S5 B-1: 応答を作る側が読むイメージ。公開の直前に 1 回だけ作る。作れなければ索引を作れなかったときと同じく捨てる */
  builder->image = zone_image_freeze(builder, entry->domain);
  if (!builder->image) {
    syslog(LOG_ERR, "[Zone] Failed to build the zone image after %s for '%s'", what, entry->domain);
    return -1;
  }
  zone_arena_free_builder(builder);
  zone_version_t *standby = zone_version_new(builder);
  if (!standby) {
    syslog(LOG_ERR, "[Zone] Out of memory publishing the zone after %s for '%s'", what, entry->domain);
    return -1;
  }

  // 設定は制御スレッドが並行して入れ替えるので、読み取り区間の中で読む
  rcu_aux_read_lock();
  zone_db_snapshot_t *cur_snap = acquire_zone_snapshot();
  server_config_t *active_cfg_prelink = acquire_config_snapshot();
  const zone_config_t *zcfg = zone_entry_config(active_cfg_prelink, entry);
  additional_from_auth_t policy = (zcfg && zext(zcfg)->additional_from_auth_specified)
                                      ? zext(zcfg)->additional_from_auth
                                      : (active_cfg_prelink ? active_cfg_prelink->additional_from_auth : ADDITIONAL_AUTH_YES);
  zone_glue_track_build(standby, entry->domain, snapshot_find_view(cur_snap, entry->view_name), policy);
  build_zone_response_cache(standby, active_cfg_prelink, entry);
  release_config_snapshot(active_cfg_prelink);
  rcu_aux_read_unlock();

  compute_ixfr_diff(entry, cur_active, standby);
  zone_publish(entry, standby);
  return 0;
}

int handle_axfr_event(int tcp_fd, zone_db_entry_t *entry,
                      tcp_stream_ctx_t *stream_ctx, axfr_session_t *session,
                      tsig_key_t *tsig_key,
                      const uint8_t *req_mac, size_t req_mac_len) {
  uint8_t *msg;
  uint16_t msg_len;

  zone_arena_t tmp_arena;
  memset(&tmp_arena, 0, sizeof(tmp_arena));
  zone_arena_init(&tmp_arena);

  /* 転送の間ずっと読み取り区間の外で使う。このゾーンの arena を入れ替えるのは
   * この転送 (is_transferring で1本に限る) と制御スレッドの Pass 2 prelink だけで、
   * Pass 2 は転送中のゾーンを飛ばすので、この arena は転送の完了まで再利用されない。*/
  zone_version_t *active = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
  int ret_code = -1;

  uint8_t prior_mac[64];
  size_t prior_mac_len = 0;
  if (req_mac && req_mac_len > 0 && req_mac_len <= sizeof(prior_mac)) {
    memcpy(prior_mac, req_mac, req_mac_len);
    prior_mac_len = req_mac_len;
  }
  bool is_subsequent = false;
  uint8_t *unsigned_msgs = NULL;
  size_t unsigned_msgs_len = 0;
  size_t unsigned_msgs_cap = 0;

  while (1) {
    int ret = read_dns_tcp_message(tcp_fd, stream_ctx, &msg, &msg_len);
    if (ret < 0 || ret == 0) {
      if (unsigned_msgs) free(unsigned_msgs);
      zone_arena_destroy(&tmp_arena);
      return -1;
    }
    int hdr = xfr_check_response_header(msg, msg_len, session, entry->domain);
    if (hdr != 0) {
      if (hdr > 0 && tsig_key && !is_subsequent) {
        /* エラー応答の TSIG を調べてログに出す (RFC 8945 §5.3.2: プライマリが要求の TSIG を
         * 受け付けなかったときは MAC の無い TSIG で Error に BADKEY/BADSIG を入れて返す) */
        uint8_t err_mac[64];
        size_t err_mac_len = 0;
        int tv = tsig_verify_packet(msg, msg_len, tsig_key, prior_mac_len > 0 ? prior_mac : NULL, prior_mac_len,
                                    NULL, 0, false, err_mac, &err_mac_len);
        if (tv == 16 || tv == 17)
          syslog(LOG_WARNING, "[AXFR] zone '%s': the primary rejected our TSIG key '%s' (%s)", entry->domain,
                 tsig_key->name ? tsig_key->name : "", tv == 17 ? "BADKEY" : "BADSIG");
        else if (tv != 0)
          syslog(LOG_WARNING, "[AXFR] zone '%s': the error response is not signed with key '%s'", entry->domain,
                 tsig_key->name ? tsig_key->name : "");
      }
      if (unsigned_msgs) free(unsigned_msgs);
      zone_arena_destroy(&tmp_arena);
      return -1;
    }
    if (tsig_key) {
      bool has_tsig = packet_has_tsig(msg, msg_len);
      if (!has_tsig) {
        if (!is_subsequent) {
          syslog(LOG_ERR, "[AXFR] First message missing TSIG");
          if (unsigned_msgs) free(unsigned_msgs);
          zone_arena_destroy(&tmp_arena);
          return -1;
        }
        if (msg_len > 0) {
          if (unsigned_msgs_len + msg_len > unsigned_msgs_cap) {
            size_t new_cap = unsigned_msgs_cap == 0 ? 65536 : unsigned_msgs_cap * 2;
            while (new_cap < unsigned_msgs_len + msg_len) new_cap *= 2;
            uint8_t *new_buf = realloc(unsigned_msgs, new_cap);
            if (!new_buf) {
              if (unsigned_msgs) free(unsigned_msgs);
              zone_arena_destroy(&tmp_arena);
              return -1;
            }
            unsigned_msgs = new_buf;
            unsigned_msgs_cap = new_cap;
          }
          if (unsigned_msgs && msg) {
            memcpy(unsigned_msgs + unsigned_msgs_len, msg, msg_len);
            unsigned_msgs_len += msg_len;
          }
        }
      } else {
        uint8_t current_mac[64];
        size_t current_mac_len = 0;
        if (tsig_verify_packet(msg, msg_len, tsig_key,
                               prior_mac_len > 0 ? prior_mac : NULL, prior_mac_len,
                               unsigned_msgs_len > 0 ? unsigned_msgs : NULL, unsigned_msgs_len,
                               is_subsequent,
                               current_mac, &current_mac_len) != 0) {
          syslog(LOG_ERR, "[AXFR] TSIG failed");
          if (unsigned_msgs) free(unsigned_msgs);
          zone_arena_destroy(&tmp_arena);
          return -1;
        }
        unsigned_msgs_len = 0;
        if (current_mac_len > 0 && current_mac_len <= sizeof(prior_mac)) {
          memcpy(prior_mac, current_mac, current_mac_len);
          prior_mac_len = current_mac_len;
          is_subsequent = true;
        }
      }
    }
    if (parse_xfr_packet(msg, msg_len, &tmp_arena, active, session,
                         entry->domain) != 0) {
      if (unsigned_msgs) free(unsigned_msgs);
      zone_arena_destroy(&tmp_arena);
      return -1;
    }
    if (session->is_finished) {
      if (tsig_key && unsigned_msgs_len > 0) {
        syslog(LOG_ERR, "[AXFR] Final message unsigned or intermediate TSIG missing");
        if (unsigned_msgs) free(unsigned_msgs);
        zone_arena_destroy(&tmp_arena);
        return -1;
      }
      if (unsigned_msgs) { free(unsigned_msgs); unsigned_msgs = NULL; }
      if (tmp_arena.count > 0) {
        uint32_t serial = 0, refresh = 0, retry = 0, expire = 0;
        bool has_soa = false;
        /* S5 B-2: an RR that cannot be written in wire format is dropped with a warning and the rest is applied
         * (the same as a zone file; the published image holds only RRs that can be served) */
        zone_drop_unencodable_logged(&tmp_arena, entry->domain, "the zone transfer");
        for (size_t k = 0; k < tmp_arena.count; k++) {
          if (tmp_arena.records[k].type_code == 6 &&
              domain_names_match_ci(tmp_arena.records[k].name, entry->domain) &&
              tmp_arena.records[k].rdata_count >= 7) {
            serial = strtoul(tmp_arena.records[k].rdata[2], NULL, 10);
            refresh = parse_ttl_value(tmp_arena.records[k].rdata[3]);
            retry = parse_ttl_value(tmp_arena.records[k].rdata[4]);
            expire = parse_ttl_value(tmp_arena.records[k].rdata[5]);
            has_soa = true;
            break;
          }
        }

        pthread_mutex_lock(&entry->writer_lock);
        if (!wait_for_active_axfr(entry, 5000)) {
          pthread_mutex_unlock(&entry->writer_lock);
          if (unsigned_msgs) free(unsigned_msgs);
          zone_arena_destroy(&tmp_arena);
          syslog(LOG_WARNING, "[XFR] Inbound transfer swap for zone '%s' postponed: active AXFR in progress.", entry->domain);
          return -1;
        }
        if (has_soa) {
          time_t now = time(NULL);
          entry->serial = serial;
          entry->refresh = refresh;
          entry->retry = retry;
          entry->expire = expire;
          atomic_store_explicit(&entry->next_check, now + entry->refresh, memory_order_release);
          atomic_store_explicit(&entry->expire_at,
                                xfr_expire_deadline(true, session->has_expire, session->expire, expire, 0, now),
                                memory_order_release);
          atomic_store_explicit(&entry->last_successful_transfer, now, memory_order_release);
        }

        /* S5 B-2: the received zone (tmp_arena) is the builder; only its image is published (S5 B-3: as a new version) */
        if (zone_install_builder(entry, &tmp_arena, "XFR") != 0) {
          pthread_mutex_unlock(&entry->writer_lock);
          if (unsigned_msgs) free(unsigned_msgs);
          zone_arena_destroy(&tmp_arena);
          return -1;
        }
        pthread_mutex_unlock(&entry->writer_lock);

        if (session->is_ixfr) {
          atomic_fetch_add_explicit(&entry->observatory.ixfr_success, 1, memory_order_relaxed);
        } else {
          atomic_fetch_add_explicit(&entry->observatory.axfr_success, 1, memory_order_relaxed);
        }
        atomic_store_explicit(&entry->observatory.last_transfer_time, (uint64_t)time(NULL), memory_order_relaxed);

        // RFC 1996 §4.6: 自分もプライマリとして下流へ通知する (送信と再送は制御スレッド)
        notify_request_send(entry);
        ret_code = 1;
      } else {
        pthread_mutex_lock(&entry->writer_lock);
        time_t now = time(NULL);
        atomic_store_explicit(&entry->next_check, now + entry->refresh, memory_order_release);
        atomic_store_explicit(&entry->expire_at,
                              xfr_expire_deadline(false, session->has_expire, session->expire, entry->expire,
                                                  zone_expire_deadline(entry), now),
                              memory_order_release);
        atomic_store_explicit(&entry->last_successful_transfer, now, memory_order_release);
        pthread_mutex_unlock(&entry->writer_lock);
        ret_code = 2;
      }
      break;
    }
  }

  if (unsigned_msgs) free(unsigned_msgs);
  zone_arena_destroy(&tmp_arena);

  // Hook for catalog zone processing
  // zcfg は設定の中を指し、catalog_process_membership() の最後まで使われるので区間で守る。
  // この区間の中で rcu_writer_wait_until_safe() を呼ぶ経路は無い (カタログの差分更新は
  // rebuild_zone_db_snapshot() の構築と公開だけで、解放は GC スレッドが待つ)。
  rcu_aux_read_lock();
  server_config_t *cfg = acquire_config_snapshot();
  const zone_config_t *zcfg = zone_entry_config(cfg, entry);
  if (zcfg && zcfg->is_catalog) {
      catalog_process_membership(entry, zcfg, entry->view_name);
  }
  release_config_snapshot(cfg);
  rcu_aux_read_unlock();
  return ret_code;
}

/* 転送要求 (AXFR、serial が 0 でなければ IXFR) を TCP の長さ前置き付きで buf に組み立てる。
 * IXFR の Authority にはクライアントの版の SOA (RFC 1995 §3)、OPT には長さ 0 の EXPIRE (RFC 7314 §4) と
 * Extended AXFR を付け、鍵があれば署名する (req_mac に要求の MAC)。戻り値は全体の長さ、失敗は 0。 */
static size_t build_xfr_request(uint8_t *buf, size_t cap, const char *domain, uint32_t serial, uint16_t id,
                                tsig_key_t *tsig_key, uint8_t *req_mac, size_t *req_mac_len) {
  uint8_t *hdr = &buf[2];
  size_t len = 2;
  if (cap < 2 + DNS_HEADER_SIZE + UDP_DEFAULT_MAX_RES_LEN) return 0;
  memset(hdr, 0, DNS_HEADER_SIZE);
  hdr[0] = id >> 8;
  hdr[1] = id & 0xFF;
  hdr[5] = 0x01;
  hdr[9] = serial ? 0x01 : 0x00;
  len += DNS_HEADER_SIZE;
  long w = write_uncompressed_name(buf, len, cap - UDP_DEFAULT_MAX_RES_LEN, domain);
  if (w <= 0) return 0;
  len += (size_t)w;
  buf[len++] = 0x00;
  buf[len++] = serial ? 251 : 252;
  buf[len++] = 0x00;
  buf[len++] = 1;
  if (serial) {
    /* 所有者名は QNAME への圧縮ポインタ、MNAME と RNAME は root、SERIAL の後は 0 */
    static const uint8_t soa_head[] = {0xC0, 0x0C, 0x00, 6, 0x00, 1, 0, 0, 0, 0, 0x00, 22, 0, 0};
    memcpy(&buf[len], soa_head, sizeof(soa_head));
    len += sizeof(soa_head);
    buf[len++] = serial >> 24;
    buf[len++] = (serial >> 16) & 0xFF;
    buf[len++] = (serial >> 8) & 0xFF;
    buf[len++] = serial & 0xFF;
    memset(&buf[len], 0, 16);
    len += 16;
  }
  uint32_t domain_hash = calc_fnv1a_str(domain);
  const uint8_t opt[] = {
      0, 0x00, 41, 0x10, 0x00, 0, 0, 0, 0,
      0x00, 0x0D, /* RDLEN: 4 (EXPIRE) + 9 (Extended AXFR) */
      0x00, EDNS_OPTION_EXPIRE, 0x00, 0x00,
      (EDNS_OPTION_KARIDNS_EXT >> 8) & 0xFF, EDNS_OPTION_KARIDNS_EXT & 0xFF, 0x00, 0x05,
      KARIDNS_EXT_VERSION, (domain_hash >> 24) & 0xFF, (domain_hash >> 16) & 0xFF, (domain_hash >> 8) & 0xFF,
      domain_hash & 0xFF};
  memcpy(&buf[len], opt, sizeof(opt));
  len += sizeof(opt);
  hdr[11] = 1;
  *req_mac_len = 0;
  if (tsig_key) {
    size_t p_len = len - 2;
    if (tsig_sign_packet(hdr, &p_len, cap - 2, tsig_key, 0, req_mac, req_mac_len, NULL, 0, false) != 0)
      return 0;
    len = p_len + 2;
  }
  buf[0] = (uint8_t)((len - 2) >> 8);
  buf[1] = (uint8_t)((len - 2) & 0xFF);
  return len;
}

/* 1回の転送: 接続し、要求を送り、応答を処理する。戻り値は handle_axfr_event() と同じ
 * (1 = 転送した、2 = 最新、-1 = 失敗。エラー応答なら session->rcode にその RCODE)。 */
static int xfr_attempt(axfr_bg_ctx_t *ctx, struct sockaddr_storage *master_addr, int family,
                       tsig_key_t *tsig_key, uint32_t ixfr_serial, axfr_session_t *session) {
  uint32_t active_serial = ctx->entry ? ctx->entry->serial : 0;
  memset(session, 0, sizeof(*session));
  session->query_id = (uint16_t)(arc4random() & 0xFFFF);
  session->query_type = ixfr_serial ? 251 : 252;
  session->is_ixfr = ixfr_serial != 0;
  /* AXFR に切り替えたときも、手元より古い版は受け取らない (parse_xfr_packet() のロールバック検査) */
  session->client_serial = active_serial;

  size_t addr_len = (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
  int tcp_fd = broker_connect_opts(family, SOCK_STREAM, (struct sockaddr *)master_addr, addr_len,
                                   &ctx->tcp_opts);
  if (tcp_fd < 0) {
    syslog(LOG_ERR, "[AXFR] Failed to connect to %s for zone %s", ctx->master_ip, ctx->domain);
    return -1;
  }
  limit_client_socket_rights(tcp_fd);
  struct timeval tv;
  tv.tv_sec = 30;
  tv.tv_usec = 0;
  setsockopt(tcp_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
  setsockopt(tcp_fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof tv);
  tcp_stream_ctx_t *stream_ctx = calloc(1, sizeof(tcp_stream_ctx_t));
  if (!stream_ctx) {
    close(tcp_fd);
    syslog(LOG_ERR, "[AXFR] Failed to allocate memory for stream_ctx");
    return -1;
  }
  uint8_t axfr_req[2048];
  uint8_t req_mac[64];
  size_t req_mac_len = 0;
  int axfr_res = -1;
  size_t req_len = build_xfr_request(axfr_req, sizeof(axfr_req), ctx->domain, ixfr_serial, session->query_id,
                                     tsig_key, req_mac, &req_mac_len);
  if (req_len == 0) {
    syslog(LOG_ERR, "[AXFR] Failed to build%s request for zone %s", tsig_key ? " TSIG-signed" : "", ctx->domain);
  } else if (send(tcp_fd, axfr_req, req_len, 0) == (ssize_t)req_len) {
    // handle_axfr_event() は writer_lock を持ったまま読み取り区間に入るので、先にスロットを確保する
    rcu_aux_thread_pin();
    axfr_res = handle_axfr_event(tcp_fd, ctx->entry, stream_ctx, session, tsig_key,
                                 req_mac_len > 0 ? req_mac : NULL, req_mac_len);
    rcu_aux_thread_unpin();
  } else {
    syslog(LOG_ERR, "[AXFR] Failed to send request for zone %s to %s", ctx->domain, ctx->master_ip);
  }
  free(stream_ctx);
  close(tcp_fd);
  return axfr_res;
}

void *axfr_bg_thread_func(void *arg) {
  atomic_fetch_add_explicit(&g_xfers_running, 1, memory_order_relaxed);
  axfr_bg_ctx_t *ctx = (axfr_bg_ctx_t *)arg;
  zone_db_snapshot_t *bg_snap = ctx->snap;

  /* [H-4] ctx->has_tsig が真の場合は、ctx 内に値コピーされた TSIG 情報から
   * スタック上の tsig_key_t を組み立てて使用する (config ポインタを参照しない)。*/
  tsig_key_t local_tsig_key;
  tsig_key_t *tsig_key_ptr = NULL;
  if (ctx->has_tsig) {
    memset(&local_tsig_key, 0, sizeof(local_tsig_key));
    local_tsig_key.name = ctx->tsig_name;
    local_tsig_key.algorithm = ctx->tsig_algorithm;
    local_tsig_key.secret = NULL; /* 使用しないので NULL 可 */
    memcpy(local_tsig_key.secret_decoded, ctx->tsig_secret_decoded, ctx->tsig_secret_decoded_len);
    local_tsig_key.secret_decoded_len = ctx->tsig_secret_decoded_len;
    local_tsig_key.next = NULL;
    tsig_key_ptr = &local_tsig_key;
  }
  struct sockaddr_storage master_addr;
  memset(&master_addr, 0, sizeof(master_addr));
  int domain_family = AF_INET;
  if (inet_pton(AF_INET, ctx->master_ip,
                &((struct sockaddr_in *)&master_addr)->sin_addr) == 1) {
    domain_family = AF_INET;
    master_addr.ss_family = AF_INET;
    ((struct sockaddr_in *)&master_addr)->sin_port =
        htons(ctx->master_port > 0 ? ctx->master_port : 53);
  } else if (inet_pton(AF_INET6, ctx->master_ip,
                       &((struct sockaddr_in6 *)&master_addr)->sin6_addr) ==
             1) {
    domain_family = AF_INET6;
    master_addr.ss_family = AF_INET6;
    ((struct sockaddr_in6 *)&master_addr)->sin6_port =
        htons(ctx->master_port > 0 ? ctx->master_port : 53);
  } else {
    syslog(LOG_ERR, "[AXFR] Invalid master IP address format: '%s'", ctx->master_ip);
    if (ctx->entry)
      atomic_store_explicit(&ctx->entry->is_transferring, false, memory_order_release);
    free(ctx);
    if (bg_snap)
      release_zone_snapshot(bg_snap);
    atomic_fetch_sub_explicit(&g_xfers_running, 1, memory_order_relaxed);
    pthread_exit(NULL);
  }

  axfr_session_t session;
  uint32_t active_serial = ctx->entry ? ctx->entry->serial : 0;
  int axfr_res = xfr_attempt(ctx, &master_addr, domain_family, tsig_key_ptr, active_serial, &session);
  /* R-19, RFC 1995 §4: IXFR を扱えないプライマリ (FORMERR / NOTIMP) からは AXFR で1回だけ取り直す */
  if (axfr_res < 0 && active_serial != 0 && (session.rcode == 1 || session.rcode == 4)) {
    syslog(LOG_NOTICE, "[AXFR] zone %s: %s does not support IXFR, retrying with AXFR", ctx->domain, ctx->master_ip);
    axfr_res = xfr_attempt(ctx, &master_addr, domain_family, tsig_key_ptr, 0, &session);
  }
  if (session.out_of_zone_skipped > 0) {
    syslog(LOG_WARNING, "[AXFR] zone %s: ignored %u out-of-zone record(s) sent by %s",
           ctx->domain, session.out_of_zone_skipped, ctx->master_ip);
  }
  if (axfr_res == 1) {
    syslog(LOG_NOTICE, "[AXFR] Successfully transferred zone %s from %s", ctx->domain, ctx->master_ip);
  } else if (axfr_res == 2) {
    // Zone is up to date. Do not log to avoid spam on short refresh intervals.
  } else {
    syslog(LOG_ERR, "[AXFR] Failed to transfer zone %s from %s", ctx->domain, ctx->master_ip);
  }
  if (ctx->entry)
    atomic_store_explicit(&ctx->entry->is_transferring, false,
                          memory_order_release);
  free(ctx);
  if (bg_snap)
    release_zone_snapshot(bg_snap);
  atomic_fetch_sub_explicit(&g_xfers_running, 1, memory_order_relaxed);
  pthread_exit(NULL);
}

#ifndef KARIDNS_AXFR_MSG_LIMIT
#define KARIDNS_AXFR_MSG_LIMIT 65000
#endif

typedef struct {
  uint8_t *res;
  uint16_t offset;
  uint16_t q_offset;
  uint16_t answers;
  compress_ctx_t comp_ctx;
  const uint8_t *req;
  int client_fd;
  bool is_extended_axfr;
  bool send_opt;         /* 最初のメッセージに OPT を付ける (Extended AXFR / RFC 7314 EXPIRE) */
  bool opt_sent;
  bool is_subsequent;
  tsig_key_t *tsig_key;
  uint8_t tsig_mac[64];
  size_t tsig_mac_len;
  edns_info_t resp_edns;
  const struct sockaddr_storage *client_addr;
  socklen_t client_len;
  const struct sockaddr_storage *server_addr;
  bool has_server_addr;
  const char *domain;
} axfr_emit_ctx_t;

/* One RR to send: a builder record (IXFR history, KariDNS markers) or RR `rr` of a zone image (S5 B-2: the zone itself) */
static int axfr_write_item(axfr_emit_ctx_t *ec, const dns_record_t *rec, const zone_image_t *img, uint32_t rr) {
  if (img) return image_serialize_rr(img, rr, ec->res, KARIDNS_AXFR_MSG_LIMIT, &ec->offset, &ec->comp_ctx, NULL,
                                     zone_image_rr_ttl(img, rr));
  return serialize_dns_record(ec->res, KARIDNS_AXFR_MSG_LIMIT, &ec->offset, rec, &ec->comp_ctx, NULL, 0xFFFFFFFF);
}

static int axfr_emit_item(axfr_emit_ctx_t *ec, const dns_record_t *rec, const zone_image_t *img, uint32_t rr) {
  uint16_t prev_offset = ec->offset;
  if (axfr_write_item(ec, rec, img, rr) < 0) {
    ec->res[6] = (uint8_t)(ec->answers >> 8);
    ec->res[7] = (uint8_t)(ec->answers & 0xFF);
    if (ec->send_opt && !ec->opt_sent) {
      uint16_t arcount = 0;
      assemble_edns_opt(ec->res, 65535, &prev_offset, &arcount, &ec->resp_edns, 0, true, NULL);
      ec->res[10] = (arcount >> 8) & 0xFF;
      ec->res[11] = arcount & 0xFF;
      ec->opt_sent = true;
    }
    if (ec->tsig_key) {
      size_t sign_len = prev_offset;
      if (tsig_sign_packet(ec->res, &sign_len, 65535, ec->tsig_key, 0, ec->tsig_mac,
                           &ec->tsig_mac_len, NULL, 0, ec->is_subsequent) != 0) {
        return -1;
      }
      ec->is_subsequent = true;
      prev_offset = (uint16_t)sign_len;
    }
    write_dnstap_event(NULL, 2 /*AUTH_RESPONSE*/, ec->res, prev_offset,
                       (const struct sockaddr *)ec->client_addr, ec->client_len,
                       ec->has_server_addr ? (const struct sockaddr *)ec->server_addr : NULL,
                       ec->has_server_addr, IPPROTO_TCP);
    if (send_tcp_dns_message(ec->client_fd, ec->res, prev_offset) < 0) return -1; /* RFC 7766 §8 */

    /* 次のパケットの準備（QDCOUNT=1 と質問セクションを必ず引き継ぐ） */
    ec->offset = ec->q_offset;
    ec->answers = 0;
    memset(ec->res, 0, 65535);
    memcpy(ec->res, ec->req, ec->q_offset); /* クエリのヘッダと質問セクションをそのままコピー */
    dns_init_response_header(ec->res, ec->req, 0, true); /* QR=1 AA=1、RA/Z/AD/TC は写さない (R-05) */
    ec->res[8] = 0; ec->res[9] = 0; ec->res[10] = 0; ec->res[11] = 0;

    memset(&ec->comp_ctx, 0, sizeof(ec->comp_ctx));
    compress_ctx_init_packet(&ec->comp_ctx);
    /* パケットバッファを破壊せず質問セクションの名前を圧縮テーブルに登録 */
    register_wire_name_for_compression(ec->res, DNS_HEADER_SIZE, &ec->comp_ctx);

    if (axfr_write_item(ec, rec, img, rr) < 0) {
      syslog(LOG_ERR, "[AXFR] Record too large to fit in any TCP message (name=%s type=%u), aborting transfer",
             img ? zone_image_name_text(img, zone_image_rr_name(img, rr)) : (rec->name ? rec->name : "(null)"),
             img ? zone_image_rr_type(img, rr) : rec->type_code);
      return -1;
    }
  }
  ec->answers++;
  return 0;
}

static int axfr_emit_record(axfr_emit_ctx_t *ec, const dns_record_t *rec) { return axfr_emit_item(ec, rec, NULL, 0); }

/* A zone RR (builder record of the IXFR history, or image RR) with the Extended AXFR state markers around it */
static int axfr_emit_zone_item(axfr_emit_ctx_t *ec, const dns_record_t *rec_item, const zone_image_t *img, uint32_t rr,
                               const char **cur_loc_io, const char **cur_ecs_io) {
  const zone_image_ext_t *ext = img ? zone_image_rr_ext(img, rr) : NULL;
  const char *item_loc_tag = img ? (ext ? zone_image_str(img, ext->loc_tag_off) : NULL) : rec_item->bind_location_tag;
  const char *item_ecs_tag = img ? (ext ? zone_image_str(img, ext->ecs_tag_off) : NULL) : rec_item->ecs_subnet_tag;
  const char *item_tloc = img ? (ext ? ext->loc : "\0") : rec_item->tinydns_loc;
  int64_t item_ttd = img ? (ext ? ext->ttd : 0) : (int64_t)rec_item->tinydns_ttd;
  if (!ec->is_extended_axfr) {
    if (item_loc_tag != NULL || item_ecs_tag != NULL || item_tloc[0] != 0 || item_tloc[1] != 0 || item_ttd != 0) {
      /* Skip tagged records in fallback mode */
      return 0;
    }
    return axfr_emit_item(ec, rec_item, img, rr);
  }

  const char *r_loc = item_loc_tag ? item_loc_tag : "";
  if (strcasecmp(r_loc, *(cur_loc_io) ? *(cur_loc_io) : "") != 0) {
    dns_record_t set_rec;
    memset(&set_rec, 0, sizeof(set_rec));
    set_rec.name = (char *)ec->domain;
    set_rec.type_code = DNS_TYPE_KARIDNS_LOC_STATE;
    set_rec.class_val = DNS_CLASS_KARIDNS_EXT;
    set_rec.class_str = "KARIDNS";
    set_rec.generic_data = (uint8_t *)r_loc;
    set_rec.generic_len = strlen(r_loc);
    if (axfr_emit_record(ec, &set_rec) < 0) return -1;
    *(cur_loc_io) = item_loc_tag;
  }
  const char *r_ecs = item_ecs_tag ? item_ecs_tag : "";
  if (strcasecmp(r_ecs, *(cur_ecs_io) ? *(cur_ecs_io) : "") != 0) {
    dns_record_t set_rec;
    memset(&set_rec, 0, sizeof(set_rec));
    set_rec.name = (char *)ec->domain;
    set_rec.type_code = DNS_TYPE_KARIDNS_ECS_STATE;
    set_rec.class_val = DNS_CLASS_KARIDNS_EXT;
    set_rec.class_str = "KARIDNS";
    set_rec.generic_data = (uint8_t *)r_ecs;
    set_rec.generic_len = strlen(r_ecs);
    if (axfr_emit_record(ec, &set_rec) < 0) return -1;
    *(cur_ecs_io) = item_ecs_tag;
  }
  if (item_tloc[0] != 0 || item_tloc[1] != 0 || item_ttd != 0) {
    dns_record_t wrap_rec;
    uint8_t wrap_buf[4096];
    if (img ? wrap_tinydns_image_rr(img, rr, &wrap_rec, wrap_buf, sizeof(wrap_buf))
            : wrap_tinydns_record(rec_item, &wrap_rec, wrap_buf, sizeof(wrap_buf))) {
      return axfr_emit_record(ec, &wrap_rec);
    } else {
      return axfr_emit_item(ec, rec_item, img, rr);
    }
  }
  return axfr_emit_item(ec, rec_item, img, rr);
}

static int axfr_emit_zone_record(axfr_emit_ctx_t *ec, const dns_record_t *rec_item,
                                 const char **cur_loc_io, const char **cur_ecs_io) {
  return axfr_emit_zone_item(ec, rec_item, NULL, 0, cur_loc_io, cur_ecs_io);
}

/* 転送要求への1通だけのエラー応答 (RFC 5936 §2.2: 質問セクションを写し、それで転送を終える)。
 * 質問セクションまでで切り (Rule 3)、要求に OPT があれば OPT と EDE を付け (RFC 6891 §6.1.1)、
 * 検証できた TSIG があれば同じ鍵で署名する (RFC 8945 §5.3)。aa は応答の AA ビット。 */
static void axfr_send_error(int client_fd, const uint8_t *req, uint16_t req_len, uint8_t rcode, bool aa,
                            uint16_t ede_code, const char *ede_text,
                            tsig_key_t *tsig_key, const uint8_t *req_mac, size_t req_mac_len,
                            const struct sockaddr_storage *client_addr, socklen_t client_len,
                            const struct sockaddr_storage *server_addr, bool has_server_addr) {
  uint8_t res_buf[UDP_DEFAULT_MAX_RES_LEN];
  edns_info_t req_edns_r = {0};
  bool edns_ok = req_len >= DNS_HEADER_SIZE &&
                 parse_edns_opt(req, req_len, (uint16_t)((req[4] << 8) | req[5]), (uint16_t)((req[6] << 8) | req[7]),
                                (uint16_t)((req[8] << 8) | req[9]), (uint16_t)((req[10] << 8) | req[11]),
                                &req_edns_r) == 0 && req_edns_r.present;
  req_edns_r.ede_count = 0;
  if (edns_ok && ede_code != 0xFFFF) add_ede(&req_edns_r, true, ede_code, ede_text);
  int built = dns_build_error_response(req, req_len, res_buf, sizeof(res_buf), rcode, 0, 1,
                                       edns_ok ? &req_edns_r : NULL, true, NULL);
  if (built <= 0) return;
  if (aa) res_buf[2] |= 0x04;
  size_t copy_len = (size_t)built;
  if (tsig_key) {
    uint8_t mac[64];
    size_t mac_len = 0;
    if (req_mac_len > sizeof(mac)) return;
    if (req_mac_len > 0) memcpy(mac, req_mac, req_mac_len);
    mac_len = req_mac_len;
    if (tsig_sign_packet(res_buf, &copy_len, sizeof(res_buf), tsig_key, 0, mac, &mac_len, NULL, 0, false) != 0)
      return;
  }
  write_dnstap_event(NULL, 2 /*AUTH_RESPONSE*/, res_buf, copy_len,
                     (const struct sockaddr *)client_addr, client_len,
                     has_server_addr ? (const struct sockaddr *)server_addr : NULL,
                     has_server_addr, IPPROTO_TCP);
  send_tcp_dns_message(client_fd, res_buf, copy_len); /* RFC 7766 §8 */
}

/* Extended AXFR (KariDNS 拡張) でしか運べないデータがゾーンにあるか。無ければ拡張を求める
 * KariDNS セカンダリの IXFR にも差分で答えられる (X-24)。セカンダリは IXFR を受けると
 * 自分の active を複製して差分を当てるので、拡張データの更新はこの判定で AXFR に回す。 */
static bool zone_needs_extended_axfr(const zone_image_t *zone, const zone_db_entry_t *entry) {
  if (zone_image_has_zattr(zone) || (zone->flags & ZONE_IMAGE_F_TINYDNS))
    return true;
  bool cfg_trusted = false;
  server_config_t *cfg = acquire_config_snapshot();
  if (cfg) {
    const zone_config_t *zcfg = zone_entry_config(cfg, entry);
    cfg_trusted = (zcfg && zext(zcfg)->ecs_trusted_resolvers_count > 0) || cfg->ecs_trusted_resolvers_count > 0;
    release_config_snapshot(cfg);
  }
  return cfg_trusted;
}

void send_axfr_response(int client_fd, const char *qname __attribute__((unused)), uint8_t *req,
                        uint16_t req_len, tsig_key_t *tsig_key, zone_db_entry_t *entry,
                        uint8_t *req_mac, size_t req_mac_len,
                        const struct sockaddr_storage *client_addr, socklen_t client_len,
                        const struct sockaddr_storage *server_addr, bool has_server_addr) {
  if (!entry) {
    /* 権威を持たないゾーンへの転送要求: REFUSED、AA=0 (R-06) */
    axfr_send_error(client_fd, req, req_len, 5, false, 0xFFFF, NULL, tsig_key, req_mac, req_mac_len,
                    client_addr, client_len, server_addr, has_server_addr);
    return;
  }
  /* arena は呼び出し側 (axfr_worker_thread) の読み取り区間 (rcu_aux_read_lock) と entry->active_axfr
   * (writer は wait_for_active_axfr() で待つ) で守られる。X-03: arena の reader_count は待つ側が
   * 無かったので削除した。 */
  zone_version_t *current_arena = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
  const zone_image_t *current_zone = current_arena->image;
  if (!current_zone || current_zone->n_rrs == 0) {
    /* X-19: まだデータの無いゾーン (未転送のセカンダリなど)。何も送らないとクライアントは
     * タイムアウトまで待つので、SERVFAIL と EDE 14 Not Ready (RFC 8914 §4.15) で終える。 */
    axfr_send_error(client_fd, req, req_len, 2, false, 14, "Zone not loaded", tsig_key, req_mac, req_mac_len,
                    client_addr, client_len, server_addr, has_server_addr);
    return;
  }

  uint8_t *res = calloc(1, 65535);
  if (!res) {
    return;
  }
  size_t q_offset = DNS_HEADER_SIZE;
  if (skip_wire_name(req, req_len, q_offset, &q_offset) != 0) {
      free(res);
      return;
  }
  if (q_offset + 4 > req_len) {
    q_offset = req_len;
  } else {
    q_offset += 4;
  }
  uint16_t qtype = (q_offset >= 4) ? ((req[q_offset - 4] << 8) | req[q_offset - 3]) : 0;
  bool is_ixfr = (qtype == 251);
  uint32_t client_serial = 0;
  /* RFC 1995 §3: IXFR 要求の Authority にはクライアントの版の SOA がある。無ければ FORMERR
   * (BIND も "IXFR request missing SOA" で FORMERR)。 */
  bool has_client_soa = is_ixfr && ixfr_request_client_serial(req, req_len, q_offset, &client_serial);
  if (is_ixfr && !has_client_soa) {
    free(res);
    axfr_send_error(client_fd, req, req_len, 1, false, 0xFFFF, NULL, tsig_key, req_mac, req_mac_len,
                    client_addr, client_len, server_addr, has_server_addr);
    return;
  }
  uint16_t req_qd = (req[4] << 8) | req[5];
  uint16_t req_an = (req[6] << 8) | req[7];
  uint16_t req_ns = (req[8] << 8) | req[9];
  uint16_t req_ar = (req[10] << 8) | req[11];
  edns_info_t req_edns = {0};
  bool is_extended_axfr = false;
  if (parse_edns_opt(req, req_len, req_qd, req_an, req_ns, req_ar, &req_edns) == 0) {
    if (req_edns.has_karidns_ext && req_edns.karidns_ext_version == KARIDNS_EXT_VERSION) {
      uint32_t exp_hash = calc_fnv1a_str(entry->domain);
      if (req_edns.karidns_ext_hash == exp_hash) {
        is_extended_axfr = true;
      }
    }
  }
  edns_info_t resp_edns = {0};
  /* R-16, RFC 5936 §2.2.5: 要求に OPT があれば最初のメッセージに OPT を1つ付ける */
  if (req_edns.present) resp_edns.present = true;
  if (is_extended_axfr) {
    resp_edns.present = true;
    resp_edns.has_karidns_ext = true;
    resp_edns.karidns_ext_version = KARIDNS_EXT_VERSION;
    resp_edns.karidns_ext_hash = calc_fnv1a_str(entry->domain);
  }
  /* RFC 7314 §3: EXPIRE 付きの AXFR/IXFR には SOA EXPIRE (プライマリ) または
   * expire タイマーの残り (セカンダリ) を最初のメッセージの OPT で返す。 */
  if (req_edns.has_expire_query) {
    resp_edns.present = true;
    resp_edns.send_expire = true;
    resp_edns.send_expire_value = zone_expire_option_value(entry, time(NULL));
  }

  uint32_t soa_rr = zone_image_apex_soa(current_zone);
  if (soa_rr == ZONE_IMAGE_NONE) {
    free(res);
    return;
  }

  bool send_ixfr = false;
  ixfr_txn_t *txn_list[MAX_IXFR_HISTORY];
  int txn_count = 0;
  uint32_t current_serial = 0;
  {
    zone_image_soa_t soa_nums;
    if (zone_image_soa(current_zone, soa_rr, NULL, 0, NULL, 0, &soa_nums) == 0) current_serial = soa_nums.serial;
  }
  /* Extended AXFR: the zone level tables, decoded from the image (freed at the end) */
  zone_arena_t zattr;
  zone_arena_init(&zattr);

  /* R-15, RFC 1995 §2: 同じか新しい版 (RFC 1982 の比較) を持つクライアントには現在の SOA 1件で答える。 */
  bool client_up_to_date = is_ixfr && (client_serial == current_serial ||
                                       serial_is_newer(client_serial, current_serial));
  /* X-24: 拡張を求める KariDNS セカンダリの IXFR は、拡張でしか運べないデータがあるときだけ
   * Extended AXFR にする。それ以外は通常の IXFR (差分が無ければ下で AXFR) で答える。 */
  if (is_extended_axfr && is_ixfr && !client_up_to_date && zone_needs_extended_axfr(current_zone, entry)) {
    is_ixfr = false;
  }

  if (client_up_to_date) {
    send_ixfr = true;
  } else if (is_ixfr) {
    /* RFC 1995 §4: when no incremental answer is available (no history at all with ixfr-history 0, or the client's
     * serial is older than the oldest kept diff) the whole zone is sent, AXFR style */
    pthread_mutex_lock(&entry->ixfr_history.lock);
    if (entry->ixfr_history.count > 0) {
    int start_idx = (entry->ixfr_history.head + entry->ixfr_history.cap - entry->ixfr_history.count) % entry->ixfr_history.cap;
    int found_idx = -1;
    for (int i = 0; i < entry->ixfr_history.count; i++) {
      int idx = (start_idx + i) % entry->ixfr_history.cap;
      ixfr_txn_t *txn = entry->ixfr_history.entries[idx];
      if (txn && txn->old_serial == client_serial) {
        found_idx = i;
        break;
      }
    }
    if (found_idx >= 0) {
      bool continuous = true;
      uint32_t expected_serial = client_serial;
      for (int i = found_idx; i < entry->ixfr_history.count; i++) {
        int idx = (start_idx + i) % entry->ixfr_history.cap;
        ixfr_txn_t *txn = entry->ixfr_history.entries[idx];
        if (!txn || txn->old_serial != expected_serial) {
          continuous = false;
          break;
        }
        expected_serial = txn->new_serial;
      }
      if (continuous && expected_serial == current_serial) {
        send_ixfr = true;
        for (int i = found_idx; i < entry->ixfr_history.count; i++) {
          int idx = (start_idx + i) % entry->ixfr_history.cap;
          ixfr_txn_t *txn = entry->ixfr_history.entries[idx];
          if (txn) {
            atomic_fetch_add_explicit(&txn->ref_count, 1, memory_order_acquire);
            txn_list[txn_count++] = txn;
          }
        }
      }
      }
    }
    pthread_mutex_unlock(&entry->ixfr_history.lock);
  }

  axfr_emit_ctx_t ec;
  memset(&ec, 0, sizeof(ec));
  ec.res = res;
  ec.offset = (uint16_t)q_offset;
  ec.q_offset = (uint16_t)q_offset;
  ec.answers = 0;
  ec.req = req;
  ec.client_fd = client_fd;
  ec.is_extended_axfr = is_extended_axfr;
  ec.send_opt = resp_edns.present;
  ec.opt_sent = false;
  ec.is_subsequent = false;
  ec.tsig_key = tsig_key;
  if (req_mac_len > 0) {
    memcpy(ec.tsig_mac, req_mac, req_mac_len);
    ec.tsig_mac_len = req_mac_len;
  }
  ec.resp_edns = resp_edns;
  ec.client_addr = client_addr;
  ec.client_len = client_len;
  ec.server_addr = server_addr;
  ec.has_server_addr = has_server_addr;
  ec.domain = entry->domain;

  memset(res, 0, 65535);
  memcpy(res, req, q_offset);
  dns_init_response_header(res, req, 0, true); /* QR=1 AA=1、RA/Z/AD/TC は写さない (R-05) */
  res[8] = 0;
  res[9] = 0;
  res[10] = 0;
  res[11] = 0;
  compress_ctx_init_packet(&ec.comp_ctx);
  register_wire_name_for_compression(res, DNS_HEADER_SIZE, &ec.comp_ctx);

  if (!send_ixfr && is_extended_axfr && zone_image_zattr_load(current_zone, &zattr) != 0) goto axfr_error;
  if (send_ixfr) {
    if (axfr_emit_item(&ec, NULL, current_zone, soa_rr) < 0) goto axfr_error;
    const char *ixfr_loc = NULL;
    const char *ixfr_ecs = NULL;
    for (int t = 0; t < txn_count; t++) {
      ixfr_txn_t *txn = txn_list[t];
      int soa_del_idx = -1;
      for (int i = 0; i < txn->deleted_count; i++) {
        if (txn->deleted[i].type_code == 6) { soa_del_idx = i; break; }
      }
      if (soa_del_idx >= 0) {
        if (axfr_emit_record(&ec, &txn->deleted[soa_del_idx]) < 0) goto axfr_error;
      }
      for (int i = 0; i < txn->deleted_count; i++) {
        if (i == soa_del_idx) continue;
        if (axfr_emit_zone_record(&ec, &txn->deleted[i], &ixfr_loc, &ixfr_ecs) < 0) goto axfr_error;
      }
      int soa_add_idx = -1;
      for (int i = 0; i < txn->added_count; i++) {
        if (txn->added[i].type_code == 6) { soa_add_idx = i; break; }
      }
      if (soa_add_idx >= 0) {
        if (axfr_emit_record(&ec, &txn->added[soa_add_idx]) < 0) goto axfr_error;
      }
      for (int i = 0; i < txn->added_count; i++) {
        if (i == soa_add_idx) continue;
        if (axfr_emit_zone_record(&ec, &txn->added[i], &ixfr_loc, &ixfr_ecs) < 0) goto axfr_error;
      }
    }
    if (txn_count > 0) {
      if (axfr_emit_item(&ec, NULL, current_zone, soa_rr) < 0) goto axfr_error;
    }
  } else {
    // 1. Initial SOA
    if (axfr_emit_item(&ec, NULL, current_zone, soa_rr) < 0) goto axfr_error;

    // Definitions emitted after first SOA in extended mode
    if (is_extended_axfr) {
      for (int i = 0; i < zattr.bind_location_tag_count; i++) {
        uint8_t tag_buf[2048];
        size_t dlen = pack_tag_def_rdata(tag_buf, sizeof(tag_buf), &zattr.bind_location_tags[i]);
        if (dlen > 0) {
          dns_record_t tag_rec;
          memset(&tag_rec, 0, sizeof(tag_rec));
          tag_rec.name = entry->domain;
          tag_rec.type_code = DNS_TYPE_KARIDNS_LOC_TAGDEF;
          tag_rec.class_val = DNS_CLASS_KARIDNS_EXT;
          tag_rec.class_str = "KARIDNS";
          tag_rec.generic_data = tag_buf;
          tag_rec.generic_len = dlen;
          if (axfr_emit_record(&ec, &tag_rec) < 0) goto axfr_error;
        }
      }
      for (int i = 0; i < zattr.bind_ecs_tag_count; i++) {
        uint8_t tag_buf[2048];
        size_t dlen = pack_tag_def_rdata(tag_buf, sizeof(tag_buf), &zattr.bind_ecs_tags[i]);
        if (dlen > 0) {
          dns_record_t tag_rec;
          memset(&tag_rec, 0, sizeof(tag_rec));
          tag_rec.name = entry->domain;
          tag_rec.type_code = DNS_TYPE_KARIDNS_ECS_TAGDEF;
          tag_rec.class_val = DNS_CLASS_KARIDNS_EXT;
          tag_rec.class_str = "KARIDNS";
          tag_rec.generic_data = tag_buf;
          tag_rec.generic_len = dlen;
          if (axfr_emit_record(&ec, &tag_rec) < 0) goto axfr_error;
        }
      }
      server_config_t *axfr_cfg = acquire_config_snapshot();
      const zone_config_t *axfr_zcfg = axfr_cfg ? zone_entry_config(axfr_cfg, entry) : NULL;
      char **trusted_res = (zattr.bind_ecs_trusted_resolver_count > 0 && zattr.bind_ecs_trusted_resolvers)
                            ? zattr.bind_ecs_trusted_resolvers : NULL;
      int trusted_count = trusted_res ? zattr.bind_ecs_trusted_resolver_count : 0;
      if (!trusted_res) {
        trusted_res = (axfr_zcfg && zext(axfr_zcfg)->ecs_trusted_resolvers) ? zext(axfr_zcfg)->ecs_trusted_resolvers
                                                                       : (axfr_cfg ? axfr_cfg->ecs_trusted_resolvers : NULL);
        trusted_count = (axfr_zcfg && zext(axfr_zcfg)->ecs_trusted_resolvers) ? zext(axfr_zcfg)->ecs_trusted_resolvers_count
                                                                   : (axfr_cfg ? axfr_cfg->ecs_trusted_resolvers_count : 0);
      }
      if (trusted_count > 0 && trusted_res) {
        uint8_t trusted_buf[2048];
        size_t toffset = 0;
        trusted_buf[toffset++] = (uint8_t)(trusted_count > 255 ? 255 : trusted_count);
        for (int i = 0; i < trusted_count && toffset < sizeof(trusted_buf); i++) {
          if (!trusted_res[i]) continue;
          size_t slen = strlen(trusted_res[i]);
          if (slen > 255) slen = 255;
          if (toffset + 1 + slen > sizeof(trusted_buf)) break;
          trusted_buf[toffset++] = (uint8_t)slen;
          memcpy(&trusted_buf[toffset], trusted_res[i], slen);
          toffset += slen;
        }
        dns_record_t trusted_rec;
        memset(&trusted_rec, 0, sizeof(trusted_rec));
        trusted_rec.name = entry->domain;
        trusted_rec.type_code = DNS_TYPE_KARIDNS_ECS_TRUSTED;
        trusted_rec.class_val = DNS_CLASS_KARIDNS_EXT;
        trusted_rec.class_str = "KARIDNS";
        trusted_rec.generic_data = trusted_buf;
        trusted_rec.generic_len = toffset;
        if (axfr_emit_record(&ec, &trusted_rec) < 0) {
          if (axfr_cfg) release_config_snapshot(axfr_cfg);
          goto axfr_error;
        }
      }
      if (axfr_cfg) release_config_snapshot(axfr_cfg);
      for (int i = 0; i < zattr.location_count; i++) {
        const tinydns_location_entry_t *loc = &zattr.locations[i];
        /* Extended AXFR v2: code(2) + prefix length in bits(1) + network(4) */
        uint8_t loc_buf[7];
        loc_buf[0] = loc->code[0];
        loc_buf[1] = loc->code[1];
        loc_buf[2] = loc->prefix_bits;
        memcpy(&loc_buf[3], loc->prefix, 4);
        dns_record_t loc_rec;
        memset(&loc_rec, 0, sizeof(loc_rec));
        loc_rec.name = entry->domain;
        loc_rec.type_code = DNS_TYPE_KARIDNS_TINYDNS_LOCDEF;
        loc_rec.class_val = DNS_CLASS_KARIDNS_EXT;
        loc_rec.class_str = "KARIDNS";
        loc_rec.generic_data = loc_buf;
        loc_rec.generic_len = sizeof(loc_buf);
        if (axfr_emit_record(&ec, &loc_rec) < 0) goto axfr_error;
      }
    }

    const char *current_stream_loc = NULL;
    const char *current_stream_ecs = NULL;
    /* file order (zone_image_seq_rr), as the builder was walked before */
    for (uint32_t seq = 0; seq < current_zone->n_rrs; seq++) {
      uint32_t rr = zone_image_seq_rr(current_zone, seq);
      if (rr == soa_rr)
        continue;
      if (axfr_emit_zone_item(&ec, NULL, current_zone, rr, &current_stream_loc, &current_stream_ecs) < 0) goto axfr_error;
    }

    if (is_extended_axfr) {
      if (current_stream_loc && *current_stream_loc) {
        dns_record_t set_rec;
        memset(&set_rec, 0, sizeof(set_rec));
        set_rec.name = entry->domain;
        set_rec.type_code = DNS_TYPE_KARIDNS_LOC_STATE;
        set_rec.class_val = DNS_CLASS_KARIDNS_EXT;
        set_rec.class_str = "KARIDNS";
        set_rec.generic_data = (uint8_t *)"";
        set_rec.generic_len = 0;
        if (axfr_emit_record(&ec, &set_rec) < 0) goto axfr_error;
      }
      if (current_stream_ecs && *current_stream_ecs) {
        dns_record_t set_rec;
        memset(&set_rec, 0, sizeof(set_rec));
        set_rec.name = entry->domain;
        set_rec.type_code = DNS_TYPE_KARIDNS_ECS_STATE;
        set_rec.class_val = DNS_CLASS_KARIDNS_EXT;
        set_rec.class_str = "KARIDNS";
        set_rec.generic_data = (uint8_t *)"";
        set_rec.generic_len = 0;
        if (axfr_emit_record(&ec, &set_rec) < 0) goto axfr_error;
      }
    }

    // 3. Trailing SOA
    if (axfr_emit_item(&ec, NULL, current_zone, soa_rr) < 0) goto axfr_error;
  }
  if (ec.answers > 0) {
    ec.res[6] = (uint8_t)(ec.answers >> 8);
    ec.res[7] = (uint8_t)(ec.answers & 0xFF);
    if (ec.send_opt && !ec.opt_sent) {
      uint16_t arcount = 0;
      assemble_edns_opt(ec.res, 65535, &ec.offset, &arcount, &ec.resp_edns, 0, true, NULL);
      ec.res[10] = (arcount >> 8) & 0xFF;
      ec.res[11] = arcount & 0xFF;
      ec.opt_sent = true;
    }
    if (ec.tsig_key) {
      size_t sign_len = ec.offset;
      if (tsig_sign_packet(ec.res, &sign_len, 65535, ec.tsig_key, 0, ec.tsig_mac,
                           &ec.tsig_mac_len, NULL, 0, ec.is_subsequent) != 0) {
        goto axfr_error;
      }
      ec.offset = (uint16_t)sign_len;
    }
    write_dnstap_event(NULL, 2 /*AUTH_RESPONSE*/, ec.res, ec.offset,
                       (const struct sockaddr *)client_addr, client_len,
                       has_server_addr ? (const struct sockaddr *)server_addr : NULL,
                       has_server_addr, IPPROTO_TCP);
    if (send_tcp_dns_message(client_fd, ec.res, ec.offset) < 0) /* RFC 7766 §8 */
      goto axfr_error;
  }

  for (int t = 0; t < txn_count; t++) {
    if (atomic_fetch_sub_explicit(&txn_list[t]->ref_count, 1, memory_order_acq_rel) == 1) {
       free_ixfr_txn(txn_list[t]);
    }
  }
  if (res) free(res);
  zone_arena_destroy(&zattr);
  return;

axfr_error:
  zone_arena_destroy(&zattr);
  for (int t = 0; t < txn_count; t++) {
    if (atomic_fetch_sub_explicit(&txn_list[t]->ref_count, 1, memory_order_acq_rel) == 1) {
       free_ixfr_txn(txn_list[t]);
    }
  }
  if (res) free(res);
}

void *axfr_worker_thread(void *arg) {
  atomic_fetch_add_explicit(&g_xfers_running, 1, memory_order_relaxed);
  axfr_worker_args_t *args = (axfr_worker_args_t *)arg;
  zone_db_entry_t *entry = args->entry;
  /* 転送の間、arena を読み取り区間で守る。スロットはスレッドごとに確保する
   * (以前は通し番号の剰余で割り当てており、同時に動くスレッドが同じスロットを
   * 共有すると、先に終わった側が区間を閉じてしまった)。*/
  rcu_aux_read_lock();

  tsig_key_t key_val;
  tsig_key_t *pkey = NULL;
  if (args->has_tsig) {
    memset(&key_val, 0, sizeof(key_val));
    key_val.name = args->tsig_name;
    key_val.algorithm = args->tsig_algorithm;
    key_val.secret_decoded_len = args->tsig_secret_decoded_len;
    memcpy(key_val.secret_decoded, args->tsig_secret_decoded, args->tsig_secret_decoded_len);
    pkey = &key_val;
  }
  send_axfr_response(args->client_fd, args->qname, args->req, args->req_len,
                     pkey, entry, args->tsig_mac, args->tsig_mac_len,
                     &args->client_addr, args->client_len,
                     args->has_server_addr ? &args->server_addr : NULL, args->has_server_addr);
  
  submit_response_log(LOG_ACT_SENT, args->client_ip, args->client_port, args->qname, 
                      args->qclass, args->qtype, 0, args->has_edns, args->dnssec_ok);
  
  close(args->client_fd);
  dec_tcp_clients();
  zone_db_snapshot_t *worker_snap = args->snap;
  free(args);
  if (entry)
    atomic_fetch_sub(&entry->active_axfr, 1);
  rcu_aux_read_unlock();
  release_zone_snapshot(worker_snap);
  atomic_fetch_sub_explicit(&g_xfers_running, 1, memory_order_relaxed);
  pthread_exit(NULL);
}

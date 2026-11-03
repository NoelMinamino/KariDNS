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
#include "dns_log.h"
#include <time.h>
#include <unistd.h>

/* ---- batch 4: the policy of the secondary side (transfers-in / transfers-out / transfers-per-ns, the rate limiter, the order of the
 * primaries, the time limits).  Plain functions of numbers: no socket is touched here. ---- */

_Atomic int g_xfr_in_active = 0;
_Atomic int g_xfr_out_active = 0;
/* max-transfer-time-out / max-transfer-idle-out of the outbound transfer this thread serves (send_tcp_dns_message() reads them) */
_Thread_local time_t g_tcp_send_deadline_secs = 0;
_Thread_local uint32_t g_tcp_send_idle_secs = 0;

bool xfr_counter_acquire(_Atomic int *c, uint32_t limit) {
  int cur = atomic_load_explicit(c, memory_order_relaxed);
  do {
    if (cur < 0 || (uint32_t)cur >= limit) return false;
  } while (!atomic_compare_exchange_weak_explicit(c, &cur, cur + 1, memory_order_acq_rel, memory_order_relaxed));
  return true;
}

void xfr_counter_release(_Atomic int *c) { atomic_fetch_sub_explicit(c, 1, memory_order_acq_rel); }

/* One slot per remote address that a transfer has been started from (the table never frees a slot: at most XFR_NS_SLOTS different
 * primaries; beyond that the limit is not enforced for a new address, which is logged once).  The address is folded into 64 bits; two
 * addresses that fold to the same number share a quota, which can only make the limit stricter. */
#define XFR_NS_SLOTS 256
static struct {
  _Atomic uint64_t key;   /* 0 = free */
  _Atomic int n;
} g_ns_slots[XFR_NS_SLOTS];

static uint64_t xfr_ns_key(const struct sockaddr_storage *a) {
  uint64_t h = 1469598103934665603ULL ^ a->ss_family; /* FNV-1a over the address octets (the port does not matter: "a given remote name server") */
  const uint8_t *p = NULL;
  size_t n = 0;
  if (a->ss_family == AF_INET) {
    p = (const uint8_t *)&((const struct sockaddr_in *)a)->sin_addr;
    n = 4;
  } else if (a->ss_family == AF_INET6) {
    p = (const uint8_t *)&((const struct sockaddr_in6 *)a)->sin6_addr;
    n = 16;
  }
  for (size_t i = 0; i < n; i++) h = (h ^ p[i]) * 1099511628211ULL;
  return h ? h : 1;
}

static _Atomic int *xfr_ns_slot(uint64_t key, bool create) {
  for (size_t i = 0; i < XFR_NS_SLOTS; i++) {
    size_t idx = (size_t)((key + i) % XFR_NS_SLOTS);
    uint64_t cur = atomic_load_explicit(&g_ns_slots[idx].key, memory_order_acquire);
    if (cur == key) return &g_ns_slots[idx].n;
    if (cur == 0 && create) {
      uint64_t expect = 0;
      if (atomic_compare_exchange_strong_explicit(&g_ns_slots[idx].key, &expect, key, memory_order_acq_rel, memory_order_acquire) || expect == key)
        return &g_ns_slots[idx].n;
      i--; /* somebody else took the slot: look at it again */
    }
  }
  return NULL;
}

bool xfr_ns_acquire(const struct sockaddr_storage *a, uint32_t limit) {
  _Atomic int *n = xfr_ns_slot(xfr_ns_key(a), true);
  if (!n) {
    static _Atomic bool logged = false;
    if (!atomic_exchange(&logged, true))
      syslog(LOG_WARNING, "[XFR] more than %d different primaries: transfers-per-ns is not enforced for the others", XFR_NS_SLOTS);
    return true;
  }
  return xfr_counter_acquire(n, limit);
}

void xfr_ns_release(const struct sockaddr_storage *a) {
  _Atomic int *n = xfr_ns_slot(xfr_ns_key(a), false);
  if (n) xfr_counter_release(n);
}

bool xfr_rl_take(xfr_rl_t *rl, uint32_t rate, time_t now) {
  if (rate == 0) rate = 1;
  if (rl->sec != now) {
    rl->sec = now;
    rl->used = 0;
  }
  if (rl->used >= rate) return false;
  rl->used++;
  return true;
}

uint32_t xfr_read_budget(time_t now, time_t deadline, uint32_t idle_secs, bool *expired) {
  if (expired) *expired = false;
  uint32_t b = idle_secs;
  if (deadline) {
    if (now >= deadline) {
      if (expired) *expired = true;
      return 0;
    }
    uint64_t left = (uint64_t)(deadline - now);
    if (b == 0 || left < b) b = left > UINT32_MAX ? UINT32_MAX : (uint32_t)left;
  }
  return b;
}

bool xfr_serial_behind(uint32_t ours, uint32_t theirs) { return ours != theirs && !serial_is_newer(theirs, ours); }

void xfr_run_primaries(int n, xfr_try_fn fn, void *arg, xfr_run_t *out) {
  memset(out, 0, sizeof(*out));
  out->transferred_idx = -1;
  for (int i = 0; i < n; i++) {
    int r = fn(arg, i);
    if (r != XFR_R_DEFERRED) out->tried++;
    switch (r) {
      case XFR_R_TRANSFERRED: out->transferred_idx = i; break;
      case XFR_R_UPTODATE: out->uptodate++; break;
      case XFR_R_BEHIND: out->behind++; break;
      case XFR_R_DEFERRED: out->deferred++; break;
      default: out->failed++; break;
    }
    if (r == XFR_R_TRANSFERRED) break;
  }
}

void free_ixfr_txn(ixfr_txn_t *txn) {
  if (!txn) return;
  if (txn->acct) zone_bytes_resident_add(txn->acct - 1, -(int64_t)txn->bytes);
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
  /* D1a (8.1): what the history holds counts as resident while the difference is in it (free_ixfr_txn() gives it back) */
  txn->bytes = sizeof(*txn) + ((size_t)del_count + add_count) * sizeof(dns_record_t) + txn->arena.pool_bytes;
  txn->acct = (int8_t)(1 + zone_bytes_class(entry));
  zone_bytes_resident_add(txn->acct - 1, (int64_t)txn->bytes);
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

/* B8: a record of the Extended AXFR stream of the database loader that the Backend will not take; -1 for parse_xfr_packet() */
static int xfr_ext_reject(const char *domain, const char *what) {
  syslog(LOG_WARNING, "[AXFR] zone '%s': rejecting transfer: %s", domain, what);
  return -1;
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
        if (edns.has_karidns_ext && KARIDNS_EXT_VERSION_OK(edns.karidns_ext_version)) {
          uint32_t exp_hash = calc_fnv1a_str(domain);
          if (edns.karidns_ext_hash == exp_hash) {
            session->is_extended_mode = true;
            session->ext_version = edns.karidns_ext_version;
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
    bool wrapped_soa = false; /* a 65406 wrapper around an apex SOA RR: a body RR of a version 3 stream, never the frame */
    if (rec->class_val == DNS_CLASS_KARIDNS_EXT) {
      if (type == DNS_TYPE_KARIDNS_LOC_STATE) {
        standby->count--;
        session->ext_records++;
        if (session->db_stream && rec->generic_len >= sizeof(session->current_loc_tag)) return xfr_ext_reject(domain, "a LOC_STATE tag longer than 63 octets");
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
        session->ext_records++;
        if (session->db_stream && rec->generic_len >= sizeof(session->current_ecs_tag)) return xfr_ext_reject(domain, "an ECS_STATE tag longer than 63 octets");
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
      } else if (type == DNS_TYPE_KARIDNS_LOC_TAGDEF || type == DNS_TYPE_KARIDNS_ECS_TAGDEF) {
        /* I3: a definition per record; the number of definitions and of their CIDRs is bounded (XFR_TAGDEF_MAX,
         * XFR_TAGDEF_CIDR_MAX, the style of the TINYDNS_LOCDEF limit below) on the loader's stream and on AXFR-in alike */
        bool loc = type == DNS_TYPE_KARIDNS_LOC_TAGDEF;
        ecs_tag_def_t **defs = loc ? &standby->bind_location_tags : &standby->bind_ecs_tags;
        int *ndefs = loc ? &standby->bind_location_tag_count : &standby->bind_ecs_tag_count;
        int *cap = loc ? &session->loc_tagdef_cap : &session->ecs_tagdef_cap;
        standby->count--;
        session->ext_records++;
        if (!unpack_tag_def_rdata(rec->generic_data, rec->generic_len, defs, ndefs, cap)) {
          if (session->db_stream) return xfr_ext_reject(domain, loc ? "a malformed LOC_TAGDEF" : "a malformed ECS_TAGDEF");
          continue;
        }
        if (*ndefs > XFR_TAGDEF_MAX)
          return xfr_ext_reject(domain, loc ? "more than 4096 LOC_TAGDEF records" : "more than 4096 ECS_TAGDEF records");
        session->tagdef_cidrs += (uint64_t)(*defs)[*ndefs - 1].cidr_count;
        if (session->tagdef_cidrs > XFR_TAGDEF_CIDR_MAX)
          return xfr_ext_reject(domain, "more than 65536 CIDRs in the LOC_TAGDEF / ECS_TAGDEF records");
        continue;
      } else if (type == DNS_TYPE_KARIDNS_ECS_TRUSTED) {
        standby->count--;
        session->ext_records++;
        if (session->db_stream) {
          syslog(LOG_WARNING, "[AXFR] zone '%s': rejecting transfer: ECS_TRUSTED (TYPE 65407) is not allowed in this stream (the database loader's trusted resolvers come from the zone settings)", domain);
          return -1;
        }
        unpack_trusted_resolvers_rdata(rec->generic_data, rec->generic_len, &standby->bind_ecs_trusted_resolvers, &standby->bind_ecs_trusted_resolver_count);
        if (standby->bind_ecs_trusted_resolvers_parsed) {
          free(standby->bind_ecs_trusted_resolvers_parsed);
          standby->bind_ecs_trusted_resolvers_parsed = NULL;
        }
        if (standby->bind_ecs_trusted_resolver_count > 0 && standby->bind_ecs_trusted_resolvers) {
          standby->bind_ecs_trusted_resolvers_parsed = acl_list_parse(standby->bind_ecs_trusted_resolvers, standby->bind_ecs_trusted_resolver_count);
        }
        continue;
      } else if (type == DNS_TYPE_KARIDNS_SOA_SET) {
        /* B8t-2 (v3): the opening SOA is the frame, not zone data; n apex SOA RRs follow in the body, each in a 65406 wrapper.  It
         * must come right after the opening SOA of a full transfer. */
        standby->count--;
        session->ext_records++;
        if (rec->generic_len != 3 || !rec->generic_data || (rec->generic_data[0] & 1) == 0 || session->soa_set ||
            session->soa_count != 1 || standby->count != 1 || standby->records[0].type_code != 6 ||
            standby->records[0].rdata_count < 7) {
          return xfr_ext_reject(domain, "a SOA_SET that is malformed, repeated or not right after the opening SOA");
        }
        uint32_t nbody = ((uint32_t)rec->generic_data[1] << 8) | rec->generic_data[2];
        if (nbody == 0 || nbody > KARIDNS_SOA_SET_MAX) return xfr_ext_reject(domain, "a SOA_SET that announces no apex SOA RR, or more than 4096");
        session->soa_set = true;
        session->soa_set_expected = nbody;
        session->frame_valid = true;
        session->frame_refresh = parse_ttl_value(standby->records[0].rdata[3]);
        session->frame_retry = parse_ttl_value(standby->records[0].rdata[4]);
        session->frame_expire = parse_ttl_value(standby->records[0].rdata[5]);
        standby->count = 0; /* the frame SOA is not stored */
        continue;
      } else if (type == DNS_TYPE_KARIDNS_SETTINGS) {
        /* B8t-2 (v3): the settings of the primary for this zone.  Kept as text in the session (not in the transfer's arena, which an IXFR rebuilds); the caller parses them with the
         * restricted parser once the transfer is complete.  Only for a stream that was negotiated as version 3, and never from the
         * database loader (its settings come with ZONE_BEGIN). */
        standby->count--;
        session->ext_records++;
        if (session->db_stream)
          return xfr_ext_reject(domain, "a SETTINGS record in a stream where it is not allowed (the settings of a database zone come with ZONE_BEGIN)");
        if (session->ext_version >= 3 && !session->has_settings && rec->generic_data && rec->generic_len > 0 &&
            rec->generic_len <= KARIDNS_SETTINGS_MAX) {
          memcpy(session->settings_text, rec->generic_data, rec->generic_len);
          session->settings_text[rec->generic_len] = '\0';
          session->settings_len = rec->generic_len;
          session->has_settings = true;
        } else if (session->has_settings || session->ext_version < 3) {
          syslog(LOG_WARNING, "[AXFR] zone '%s': ignoring a SETTINGS record (%s)", domain,
                 session->has_settings ? "a second one" : "the stream was not negotiated as version 3");
        } else {
          syslog(LOG_WARNING, "[AXFR] zone '%s': ignoring a SETTINGS record of %zu octets (empty or longer than %u)", domain,
                 (size_t)rec->generic_len, KARIDNS_SETTINGS_MAX);
        }
        continue;
      } else if (type == DNS_TYPE_KARIDNS_TINYDNS_LOCDEF) {
        standby->count--;
        session->ext_records++;
        standby->is_tinydns_format = true;
        if (!unpack_tinydns_loc_rdata(rec->generic_data, rec->generic_len, &standby->locations, &standby->location_count) && session->db_stream)
          return xfr_ext_reject(domain, "a malformed TINYDNS_LOCDEF");
        if (session->db_stream && standby->location_count > 4096)      /* the limit of the tinydns data parser */
          return xfr_ext_reject(domain, "more than 4096 TINYDNS_LOCDEF records");
        continue;
      } else if (type == DNS_TYPE_KARIDNS_TINYDNS_WRAP) {
        session->ext_wrapped++;
        if (session->db_stream && (!rec->generic_data || rec->generic_len < 21))
          return xfr_ext_reject(domain, "a TINYDNS_WRAP shorter than its fixed part");
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
          if (session->db_stream && 21 + (size_t)orig_rdlen > rec->generic_len)
            return xfr_ext_reject(domain, "a TINYDNS_WRAP whose RDLENGTH is longer than the record");
          if (21 + orig_rdlen <= rec->generic_len) {
            uint8_t fake_wire[4096];
            size_t fake_len = 0;
            bool reconstructed = false;
            /* 所有者名は表示形式 (\. や \DDD を含みうる)。ラベルのバイトをそのまま写すとエスケープが
             * 壊れるので、ワイヤー形式に正しく直す (大文字小文字は保つ、RFC 4343) */
            long nw = rec->name ? write_uncompressed_name_ext(fake_wire, 0, sizeof(fake_wire) - 100, rec->name, false) : -1;
            bool name_ok = nw > 0;
            fake_len = name_ok ? (size_t)nw : 1;
            if (!name_ok) fake_wire[0] = 0;
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
            if (!name_ok) fake_len = 0; /* 名前を直せない: 下の代替の経路 (root を所有者にしない) */
            size_t fake_off = 0;
            uint16_t parsed_t;
            dns_record_t unwrapped;
            memset(&unwrapped, 0, sizeof(unwrapped));
            if (fake_len > 0 &&
                parse_resource_record(fake_wire, fake_len, &fake_off, standby, &unwrapped, &parsed_t) == 0) {
              *rec = unwrapped;
              type = parsed_t;
              reconstructed = true;
              if (parsed_t == 6) wrapped_soa = true;
            }
            if (!reconstructed) {
              if (session->db_stream) return xfr_ext_reject(domain, "a TINYDNS_WRAP whose RR cannot be decoded");
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
          /* B8t-2: a version 3 stream wraps an apex SOA RR also when it has no tinydns attribute (tags only, or none) */
          if (loc[0] != 0 || loc[1] != 0 || ttd != 0 || (flags & 1)) standby->is_tinydns_format = true;
        }
      }
    }

    /* S-I1: RFC 1035 §5.2 ("all RRs in the file should have the same class") and RFC 5936 §2.2.1 (QCLASS is the class of
     * the zone requested): the zone is asked for in class IN and every RR of the answer is zone data of that class.  A
     * record of another class is not this zone's data and the transfer is refused, as the database install path does
     * (an Extended AXFR class 65302 record was taken above; a TINYDNS_WRAP's RR carries its original class). */
    if (rec->class_val != 1) {
      syslog(LOG_WARNING, "[AXFR] zone '%s': rejecting transfer: record '%s' type %u of class %u (the zone is class IN)",
             domain, rec->name ? rec->name : "", (unsigned)type, (unsigned)rec->class_val);
      return -1;
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
    if (type == 6 && wrapped_soa && session->soa_set) {
      /* B8t-2 (v3): an apex SOA RR of the zone (with its attributes), not the frame */
      uint32_t body_serial = rec->rdata_count >= 7 && rec->rdata[2] ? (uint32_t)strtoul(rec->rdata[2], NULL, 10) : 0;
      if (!domain_names_match_ci(rec->name, domain) || rec->rdata_count < 7 || body_serial != session->initial_soa_serial ||
          ++session->soa_set_seen > session->soa_set_expected) {
        return xfr_ext_reject(domain, "an apex SOA RR of the body that is not at the apex, has another serial than the frame, or is more than SOA_SET announced");
      }
      continue;
    }
    /* a SOA is read through its RDATA fields: a TINYDNS_WRAP around a SOA that cannot be decoded leaves none (found by fuzz_xfr_packet) */
    if (type == 6 && (!rec->rdata || rec->rdata_count < 3 || !rec->rdata[2]))
      return xfr_ext_reject(domain, "a SOA whose RDATA cannot be decoded");
    if (type == 6) {
      session->soa_count++;
      uint32_t current_serial = strtoul(rec->rdata[2], NULL, 10);
      if (session->soa_count == 1) {
        snprintf(session->initial_soa_name, sizeof(session->initial_soa_name), "%s", rec->name);  /* I4: DNS_NAME_TEXT_SIZE */
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
            /* the primary is behind us (RFC 1982): not a transfer to accept.  A refresh from several primaries goes on to the next one
             * (BIND zone.c refresh_callback(): "serial number received from primary < ours", quiet with multi-master); the caller
             * that sets session->eff logs it that way, the others (the database loader's stream) keep the warning. */
            session->serial_behind = true;
            if (!session->eff)
              syslog(LOG_WARNING,
                     "[AXFR] Rejecting transfer for zone '%s': received serial %u is not newer "
                     "than current serial %u (possible rollback or spoofed master)",
                     domain, current_serial, session->client_serial);
            return -1;
          }
        }
      } else if (session->soa_count == 2 && session->is_ixfr) {
        /* I1, RFC 1995 §4: an incremental response "begins with two SOA RRs, the server's current SOA followed by the
         * SOA of the client's version which is about to be replaced"; the first deleted RR of each difference sequence is
         * the older SOA.  A first sequence that does not start from our serial is not a history of our version: give the
         * IXFR up (the caller asks for an AXFR). */
        if (current_serial != session->client_serial) {
          syslog(LOG_WARNING, "[AXFR] zone '%s': rejecting IXFR: the first difference sequence starts at serial %u, not at "
                 "our serial %u (RFC 1995 §4); asking for a full transfer", domain, current_serial, session->client_serial);
          session->ixfr_bad_sequence = true;
          return -1;
        }
        /* the IXFR is applied to the version we serve now: rebuild its builder from the published image (S5 B-2) */
        if (thaw_zone_arena(active, standby) != 0) {
          syslog(LOG_ERR, "[AXFR] zone '%s': cannot rebuild the current version of the zone to apply the IXFR", domain);
          return -1;
        }
        session->loc_tagdef_cap = session->ecs_tagdef_cap = 0;   /* I3: the thawed tag arrays are exactly their count */
        session->is_deleting = true;
      } else if (session->is_ixfr && session->is_deleting) {
        /* the newer SOA that starts the added RRs of this sequence: the next sequence must start from its serial */
        session->is_deleting = false;
        session->ixfr_expected_serial = current_serial;
        for (size_t k = 0; k < standby->count - 1; k++) {
          if (standby->records[k].type_code == 6 &&
              domain_names_match_ci(standby->records[k].name, domain)) {
            standby->records[k] = standby->records[standby->count - 1];
            standby->count--;
            break;
          }
        }
      } else if (session->is_ixfr && !session->is_deleting) {
        if (current_serial == session->initial_soa_serial && session->ixfr_expected_serial == session->initial_soa_serial) {
          session->is_finished = true;
          standby->count--;
        } else if (current_serial != session->ixfr_expected_serial) {
          /* I1, RFC 1995 §4: "the differential sequences are the history of changes ... ordered oldest first newest last":
           * a deletion sequence must start where the previous one ended */
          syslog(LOG_WARNING, "[AXFR] zone '%s': rejecting IXFR: a difference sequence starts at serial %u, but the previous one "
                 "ended at serial %u (RFC 1995 §4); asking for a full transfer", domain, current_serial, session->ixfr_expected_serial);
          session->ixfr_bad_sequence = true;
          return -1;
        } else {
          session->is_deleting = true;
          standby->count--;
        }
      } else {
        if (domain_names_match_ci(session->initial_soa_name, rec->name) &&
            session->initial_soa_serial == current_serial) {
          if (session->soa_set && session->soa_set_seen != session->soa_set_expected)
            return xfr_ext_reject(domain, "the transfer ends before all the apex SOA RRs SOA_SET announced");
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
/* batch 7: max-records, max-records-per-type, max-types-per-name (and max-zone-ttl of a primary zone) apply to a zone that arrives by transfer or
 * from a database as they do to a zone file (BIND: xfrin.c and zone.c both fail on DNS_R_TOOMANYRECORDS).  The transfer calls it before it records
 * the new serial and timers of the zone, so a refused zone leaves the old version, its serial and its refresh schedule as they were (the primary is
 * asked again at the retry interval).  0 = within the limits, -1 = refused (logged) or out of memory. */
int zone_limits_gate(zone_db_entry_t *entry, zone_arena_t *builder, const char *what) {
  zone_limits_t lim;
  rcu_aux_read_lock();
  server_config_t *lim_cfg = acquire_config_snapshot();
  zone_limits_effective(lim_cfg, zone_entry_config(lim_cfg, entry), entry->view_name, &lim);
  release_config_snapshot(lim_cfg);
  rcu_aux_read_unlock();
  if (!lim.max_records && !lim.max_per_type && !lim.max_types_per_name && !lim.max_zone_ttl) return 0;
  if ((lim.max_per_type || lim.max_types_per_name) && !builder->hash_table && build_zone_index(builder, true) != 0) {
    syslog(LOG_ERR, "[Zone] Memory allocation failed while checking the limits of '%s' after %s", entry->domain, what);
    return -1;
  }
  char lim_err[320];
  if (zone_arena_check_limits(builder, &lim, lim_err, sizeof(lim_err)) < 0) {
    syslog(LOG_ERR, "[Zone] zone '%s' not installed after %s: %s", entry->domain, what, lim_err);
    return -1;
  }
  return 0;
}

int zone_install_builder(zone_db_entry_t *entry, zone_arena_t *builder, const char *what) {
  zone_version_t *cur_active = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);

  zone_arena_shrink_records(builder);
  if (build_zone_index(builder, true) != 0) {
    syslog(LOG_ERR, "[Zone] Memory allocation failed while building index after %s for '%s'", what, entry->domain);
    return -1;
  }
  if (zone_limits_gate(entry, builder, what) != 0) return -1;

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

/* The primary says the zone is up to date (an IXFR answered with the one SOA of our serial, or a SOA query with the same serial): the
 * refresh timer and the expire timer start again (RFC 1034 §4.3.5, RFC 7314 §4 for the EXPIRE option).  The timers are held to the
 * limits of the zone first (BIND zone_xfrdone(): the up-to-date answer clamps them too).  entry->writer_lock is held. */
static void xfr_note_uptodate(zone_db_entry_t *entry, const axfr_session_t *session) {
  if (session->eff) {
    uint32_t r = 0, t = 0, x = 0;
    xfr_clamp_timers(session->eff, atomic_load_explicit(&entry->refresh, memory_order_relaxed),
                     atomic_load_explicit(&entry->retry, memory_order_relaxed),
                     atomic_load_explicit(&entry->expire, memory_order_relaxed), &r, &t, &x);
    atomic_store_explicit(&entry->refresh, r, memory_order_release);
    atomic_store_explicit(&entry->retry, t, memory_order_release);
    atomic_store_explicit(&entry->expire, x, memory_order_release);
  }
  time_t now = time(NULL);
  atomic_store_explicit(&entry->next_check, now + entry->refresh, memory_order_release);
  atomic_store_explicit(&entry->expire_at,
                        xfr_expire_deadline(false, session->has_expire, session->expire, entry->expire, zone_expire_deadline(entry), now),
                        memory_order_release);
  atomic_store_explicit(&entry->last_successful_transfer, now, memory_order_release);
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
  bool first_msg = true;
  uint8_t *unsigned_msgs = NULL;
  size_t unsigned_msgs_len = 0;
  size_t unsigned_msgs_cap = 0;
  unsigned unsigned_run = 0;     /* I2: unsigned messages since the last signed one (RFC 8945 §5.3.1: at most 99) */
  uint64_t total_bytes = 0;      /* I2: octets of the messages read so far (session->max_bytes) */

  uint32_t cur_rcvtimeo = 0;  /* max-transfer-time-in / max-transfer-idle-in: the SO_RCVTIMEO now set (0 = none set by this loop) */
  while (1) {
    if (session->deadline || session->idle_secs) {
      bool expired = false;
      uint32_t budget = xfr_read_budget(time(NULL), session->deadline, session->idle_secs, &expired);
      if (expired) {
        syslog(LOG_ERR, "[AXFR] zone '%s': giving up the transfer: it took longer than max-transfer-time-in", entry->domain);
        if (unsigned_msgs) free(unsigned_msgs);
        zone_arena_destroy(&tmp_arena);
        return -1;
      }
      if (budget != cur_rcvtimeo && budget > 0) {
        struct timeval rtv = { .tv_sec = (time_t)budget, .tv_usec = 0 };
        setsockopt(tcp_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&rtv, sizeof rtv);
        cur_rcvtimeo = budget;
      }
    }
    int ret = read_dns_tcp_message(tcp_fd, stream_ctx, &msg, &msg_len);
    if (ret < 0 || ret == 0) {
      if (session->idle_secs && ret == 0) /* the read timed out (SO_RCVTIMEO): read_dns_tcp_message() reports EAGAIN as 0 */
        syslog(LOG_ERR, "[AXFR] zone '%s': giving up the transfer: no data for %u seconds (max-transfer-idle-in / max-transfer-time-in)",
               entry->domain, cur_rcvtimeo);
      if (unsigned_msgs) free(unsigned_msgs);
      zone_arena_destroy(&tmp_arena);
      return -1;
    }
    total_bytes += msg_len;
    if (session->max_bytes && total_bytes > session->max_bytes) {
      syslog(LOG_ERR, "[AXFR] zone '%s': rejecting transfer: more than %llu bytes received (max-zone-bytes)", entry->domain,
             (unsigned long long)session->max_bytes);
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
        if (++unsigned_run > XFR_TSIG_UNSIGNED_MAX) {
          /* I2, RFC 8945 §5.3.1: "MUST accept up to 99 intermediary messages without a TSIG"; a primary that signs less
           * often is not verifiable, "it SHOULD assume the connection has been hijacked, and it SHOULD close the connection" */
          syslog(LOG_ERR, "[AXFR] zone '%s': rejecting transfer: more than %u messages in a row without a TSIG (RFC 8945 §5.3.1)",
                 entry->domain, XFR_TSIG_UNSIGNED_MAX);
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
        unsigned_run = 0;
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
    if (session->max_records && (uint64_t)tmp_arena.count > session->max_records) {
      /* I2: the zone being built (after an IXFR's deletions were applied) has more RRs than the zone may have */
      syslog(LOG_ERR, "[AXFR] zone '%s': rejecting transfer: more than %llu records (max-zone-records)", entry->domain,
             (unsigned long long)session->max_records);
      if (unsigned_msgs) free(unsigned_msgs);
      zone_arena_destroy(&tmp_arena);
      return -1;
    }
    /* B8t-2: version 3 was asked for and a standard transfer came back: the primary may speak version 2 only (or no extension at
     * all).  Stop before anything is installed; the caller asks again with version 2 (xfr_ext_*), so that a secondary upgraded before
     * its primary keeps the tags and tinydns attributes. */
    if (first_msg && session->ext_probe && !session->is_extended_mode) {
      session->no_ext_answer = true;
      if (unsigned_msgs) free(unsigned_msgs);
      zone_arena_destroy(&tmp_arena);
      return -1;
    }
    first_msg = false;
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
        if (session->frame_valid) {
          /* B8t-2 (v3, several or restricted apex SOA RRs): the zone-wide values are the frame's (the reference SOA) */
          serial = session->initial_soa_serial;
          refresh = session->frame_refresh;
          retry = session->frame_retry;
          expire = session->frame_expire;
          has_soa = true;
        }
        for (size_t k = 0; !has_soa && k < tmp_arena.count; k++) {
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

        /* batch 7: a zone over max-records & co. is refused here, before the serial and the timers of the zone are replaced (zone_limits_gate()) */
        if (zone_limits_gate(entry, &tmp_arena, "XFR") != 0) {
          if (unsigned_msgs) free(unsigned_msgs);
          zone_arena_destroy(&tmp_arena);
          return -1;
        }

        /* B8t-2: the settings of the primary (v3), kept past the install; a v3 transfer without them clears the earlier ones */
        char *rx_text = NULL;
        size_t rx_len = 0;
        bool rx_apply = session->is_extended_mode && session->ext_version >= 3;
        if (rx_apply && session->has_settings) {
          rx_text = malloc(session->settings_len + 1);
          if (rx_text) {
            memcpy(rx_text, session->settings_text, session->settings_len);
            rx_text[session->settings_len] = '\0';
            rx_len = session->settings_len;
          }
        }
        pthread_mutex_lock(&entry->writer_lock);
        if (!wait_for_active_axfr(entry, 5000)) {
          pthread_mutex_unlock(&entry->writer_lock);
          if (unsigned_msgs) free(unsigned_msgs);
          zone_arena_destroy(&tmp_arena);
          free(rx_text);
          syslog(LOG_WARNING, "[XFR] Inbound transfer swap for zone '%s' postponed: active AXFR in progress.", entry->domain);
          return -1;
        }
        /* BIND zone_xfrdone(): refresh and retry are held to [min-*-time, max-*-time], expire to [refresh + retry, 24 weeks] */
        if (has_soa && session->eff) xfr_clamp_timers(session->eff, refresh, retry, expire, &refresh, &retry, &expire);
        /* the serial and the timers come with the new version and are put back when it is not installed (like the database load,
         * dns_db_install.c): a failed install leaves the zone as it was, the primary is asked again at the retry interval */
        const uint32_t old_serial = entry->serial, old_refresh = entry->refresh, old_retry = entry->retry, old_expire = entry->expire;
        const time_t old_next_check = atomic_load_explicit(&entry->next_check, memory_order_relaxed);
        const time_t old_expire_at = atomic_load_explicit(&entry->expire_at, memory_order_relaxed);
        const time_t old_last_ok = atomic_load_explicit(&entry->last_successful_transfer, memory_order_relaxed);
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
        /* the settings are in force while the data is installed (the glue and the response cache of the new version read them); when the
         * data is refused the previous settings are put back */
        zone_ext_shared_t *rx_prev = NULL;
        if (rx_apply) rx_prev = zone_rx_settings_apply_locked(entry, zone_rx_settings_parse(entry->domain, rx_text, rx_len));
        if (zone_install_builder(entry, &tmp_arena, "XFR") != 0) {
          if (rx_apply) zone_ext_shared_unref(zone_rx_settings_apply_locked(entry, rx_prev));
          entry->serial = old_serial;
          entry->refresh = old_refresh;
          entry->retry = old_retry;
          entry->expire = old_expire;
          atomic_store_explicit(&entry->next_check, old_next_check, memory_order_release);
          atomic_store_explicit(&entry->expire_at, old_expire_at, memory_order_release);
          atomic_store_explicit(&entry->last_successful_transfer, old_last_ok, memory_order_release);
          pthread_mutex_unlock(&entry->writer_lock);
          if (unsigned_msgs) free(unsigned_msgs);
          zone_arena_destroy(&tmp_arena);
          free(rx_text);
          return -1;
        }
        pthread_mutex_unlock(&entry->writer_lock);
        zone_ext_shared_unref(rx_prev);
        free(rx_text);

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
        xfr_note_uptodate(entry, session);
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
 * IXFR の Authority にはクライアントの版の SOA (RFC 1995 §3)、OPT には長さ 0 の EXPIRE (RFC 7314 §4。request-expire no なら付けない) と
 * Extended AXFR を付け、鍵があれば署名する (req_mac に要求の MAC)。soa_query なら AXFR/IXFR ではなく SOA の問い合わせ
 * (request-ixfr no: BIND の "SOA before AXFR")。pe (NULL 可) は相手の server 文 (edns no / edns-udp-size / edns-version / request-nsid)。
 * 戻り値は全体の長さ、失敗は 0。 */
static size_t build_xfr_request(uint8_t *buf, size_t cap, const char *domain, uint32_t serial, uint16_t id, uint8_t ext_ver,
                                bool request_expire, bool soa_query, tsig_key_t *tsig_key, uint8_t *req_mac, size_t *req_mac_len, const xfr_primary_t *pe) {
  uint8_t *hdr = &buf[2];
  size_t len = 2;
  bool ixfr = serial != 0 && !soa_query;
  if (cap < 2 + DNS_HEADER_SIZE + UDP_DEFAULT_MAX_RES_LEN) return 0;
  memset(hdr, 0, DNS_HEADER_SIZE);
  hdr[0] = id >> 8;
  hdr[1] = id & 0xFF;
  hdr[5] = 0x01;
  hdr[9] = ixfr ? 0x01 : 0x00;
  len += DNS_HEADER_SIZE;
  long w = write_uncompressed_name(buf, len, cap - UDP_DEFAULT_MAX_RES_LEN, domain);
  if (w <= 0) return 0;
  len += (size_t)w;
  buf[len++] = 0x00;
  buf[len++] = soa_query ? 6 : (ixfr ? 251 : 252);
  buf[len++] = 0x00;
  buf[len++] = 1;
  if (ixfr) {
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
  /* the `server` statement of the primary (batch 5): edns no leaves the OPT out; request-nsid, edns-udp-size and edns-version shape it */
  bool want_nsid = pe && !pe->no_edns && pe->request_nsid;
  bool explicit_opt = pe && !pe->no_edns && (pe->request_nsid || pe->edns_udp_size || pe->edns_version);
  uint16_t udp_size = pe && pe->edns_udp_size ? pe->edns_udp_size : 4096;
  uint16_t rdlen = (uint16_t)((request_expire ? 4 : 0) + (ext_ver ? 9 : 0) + (want_nsid ? 4 : 0));
  *req_mac_len = 0;
  if (rdlen > 0 || explicit_opt) {
    /* the root owner name, TYPE OPT, the UDP size (4096 unless edns-udp-size), no extended RCODE, the EDNS version (0 unless edns-version), no flags */
    const uint8_t opt_head[] = {0, 0x00, 41, (uint8_t)(udp_size >> 8), (uint8_t)(udp_size & 0xFF), 0, pe ? pe->edns_version : 0, 0, 0};
    memcpy(&buf[len], opt_head, sizeof(opt_head));
    len += sizeof(opt_head);
    buf[len++] = (uint8_t)(rdlen >> 8);
    buf[len++] = (uint8_t)(rdlen & 0xFF);
    if (want_nsid) {   /* RFC 5001 §2.1: an empty NSID option asks the server for its identifier */
      static const uint8_t nsid_opt[] = {0x00, 0x03, 0x00, 0x00};
      memcpy(&buf[len], nsid_opt, sizeof(nsid_opt));
      len += sizeof(nsid_opt);
    }
    if (request_expire) {
      static const uint8_t expire_opt[] = {0x00, EDNS_OPTION_EXPIRE, 0x00, 0x00};
      memcpy(&buf[len], expire_opt, sizeof(expire_opt));
      len += sizeof(expire_opt);
    }
    if (ext_ver) {
      const uint8_t ext_opt[] = {(EDNS_OPTION_KARIDNS_EXT >> 8) & 0xFF, EDNS_OPTION_KARIDNS_EXT & 0xFF, 0x00, 0x05, ext_ver,
                                 (domain_hash >> 24) & 0xFF, (domain_hash >> 16) & 0xFF, (domain_hash >> 8) & 0xFF, domain_hash & 0xFF};
      memcpy(&buf[len], ext_opt, sizeof(ext_opt));
      len += sizeof(ext_opt);
    }
    hdr[11] = 1;
  }
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

/* The TCP connection to a primary, from the local address of the primary (primaries source), else of transfer-source: the connect broker binds
 * it (port 0) before connect().  -1 = no connection (logged). */
static int xfr_connect(axfr_bg_ctx_t *ctx, const xfr_primary_t *p, struct sockaddr_storage *master_addr, int family) {
  tcp_sockopts_t o = ctx->tcp_opts;
  if (p->has_src) {
    o.has_src = 1;
    memcpy(o.src, p->src, sizeof(o.src));
  }
  size_t addr_len = (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
  int tcp_fd = broker_connect_opts(family, SOCK_STREAM, (struct sockaddr *)master_addr, addr_len, &o);
  if (tcp_fd < 0) {
    syslog(LOG_ERR, "[AXFR] Failed to connect to %s for zone %s%s", p->ip, ctx->domain,
           p->has_src ? " (from the configured transfer source address)" : "");
    return -1;
  }
  limit_client_socket_rights(tcp_fd);
  struct timeval tv;
  tv.tv_sec = 30;
  tv.tv_usec = 0;
  setsockopt(tcp_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
  setsockopt(tcp_fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof tv);
  return tcp_fd;
}

/* The serial of the one apex SOA in the answer section of a SOA response (RFC 1035 §4.1.3).  false = not a usable SOA answer. */
static bool xfr_soa_answer_serial(const uint8_t *m, size_t len, uint16_t id, uint32_t *serial) {
  if (len < DNS_HEADER_SIZE || (((uint16_t)m[0] << 8) | m[1]) != id || (m[2] & 0x80) == 0 || ((m[2] >> 3) & 0x0F) != 0 || (m[3] & 0x0F) != 0)
    return false;
  uint16_t qd = (uint16_t)((m[4] << 8) | m[5]), an = (uint16_t)((m[6] << 8) | m[7]);
  size_t off = DNS_HEADER_SIZE;
  for (uint16_t i = 0; i < qd; i++) {
    size_t next;
    if (skip_wire_name(m, len, off, &next) != 0 || next + 4 > len) return false;
    off = next + 4;
  }
  bool found = false;
  uint32_t s = 0;
  for (uint16_t i = 0; i < an; i++) {
    size_t next;
    if (skip_wire_name(m, len, off, &next) != 0 || next + 10 > len) return false;
    uint16_t type = (uint16_t)((m[next] << 8) | m[next + 1]);
    uint16_t cls = (uint16_t)((m[next + 2] << 8) | m[next + 3]);
    uint16_t rdlen = (uint16_t)((m[next + 8] << 8) | m[next + 9]);
    size_t rd = next + 10;
    if (rd + rdlen > len) return false;
    if (type == 6 && cls == 1) {
      size_t o1, o2;
      if (found || skip_wire_name(m, len, rd, &o1) != 0 || skip_wire_name(m, len, o1, &o2) != 0 || o2 + 4 > rd + rdlen) return false;
      s = ((uint32_t)m[o2] << 24) | ((uint32_t)m[o2 + 1] << 16) | ((uint32_t)m[o2 + 2] << 8) | m[o2 + 3];
      found = true;
    }
    off = rd + rdlen;
  }
  if (found) *serial = s;
  return found;
}

/* request-ixfr no (BIND 9.20: "IXFR disabled, requesting SOA before AXFR"): ask for the SOA of the zone first, over its own TCP connection,
 * and transfer only when the primary's serial is newer than ours.  Returns XFR_R_UPTODATE (same serial: the timers are restarted, with the
 * EXPIRE option of the answer), XFR_R_BEHIND, XFR_R_TRANSFERRED (= newer: transfer now) or XFR_R_FAILED. */
static int xfr_soa_probe(axfr_bg_ctx_t *ctx, const xfr_primary_t *p, struct sockaddr_storage *master_addr, int family, tsig_key_t *tsig_key,
                         uint32_t our_serial, axfr_session_t *session) {
  int fd = xfr_connect(ctx, p, master_addr, family);
  if (fd < 0) return XFR_R_FAILED;
  int result = XFR_R_FAILED;
  tcp_stream_ctx_t *sctx = calloc(1, sizeof(tcp_stream_ctx_t));
  uint8_t req[2048], req_mac[64], *msg = NULL;
  size_t req_mac_len = 0;
  uint16_t id = (uint16_t)(arc4random() & 0xFFFF), msg_len = 0;
  size_t req_len = sctx ? build_xfr_request(req, sizeof(req), ctx->domain, 0, id, 0, ctx_request_expire(ctx, p), true, tsig_key, req_mac, &req_mac_len, p) : 0;
  if (req_len == 0 || send(fd, req, req_len, 0) != (ssize_t)req_len) {
    syslog(LOG_ERR, "[AXFR] zone %s: cannot send the SOA query to %s", ctx->domain, p->ip);
  } else if (read_dns_tcp_message(fd, sctx, &msg, &msg_len) <= 0) {
    syslog(LOG_ERR, "[AXFR] zone %s: no answer to the SOA query from %s", ctx->domain, p->ip);
  } else {
    uint32_t theirs = 0;
    bool signed_ok = true;
    if (tsig_key) {
      uint8_t mac[64];
      size_t mac_len = 0;
      signed_ok = tsig_verify_packet(msg, msg_len, tsig_key, req_mac_len > 0 ? req_mac : NULL, req_mac_len, NULL, 0, false, mac, &mac_len) == 0;
      if (!signed_ok) syslog(LOG_ERR, "[AXFR] zone %s: the SOA answer of %s is not signed correctly with key '%s'", ctx->domain, p->ip, tsig_key->name);
    }
    if (signed_ok && !xfr_soa_answer_serial(msg, msg_len, id, &theirs)) {
      syslog(LOG_ERR, "[AXFR] zone %s: %s did not answer the SOA query with a SOA record", ctx->domain, p->ip);
    } else if (signed_ok) {
      if (msg_len >= DNS_HEADER_SIZE && ((msg[10] << 8) | msg[11]) > 0) {
        edns_info_t edns = {0};
        uint16_t qd = (uint16_t)((msg[4] << 8) | msg[5]), an = (uint16_t)((msg[6] << 8) | msg[7]), ns = (uint16_t)((msg[8] << 8) | msg[9]),
                 ar = (uint16_t)((msg[10] << 8) | msg[11]);
        if (parse_edns_opt(msg, msg_len, qd, an, ns, ar, &edns) == 0 && edns.has_expire_value) {
          session->has_expire = true;
          session->expire = edns.expire_value;
        }
      }
      session->initial_soa_serial = theirs;
      if (theirs == our_serial) result = XFR_R_UPTODATE;
      else if (xfr_serial_behind(our_serial, theirs)) result = XFR_R_BEHIND;
      else result = XFR_R_TRANSFERRED;
    }
  }
  free(sctx);
  close(fd);
  return result;
}

/* 1回の転送: 接続し、要求を送り、応答を処理する。戻り値は handle_axfr_event() と同じ
 * (1 = 転送した、2 = 最新、-1 = 失敗。エラー応答なら session->rcode にその RCODE)。 */
static int xfr_attempt(axfr_bg_ctx_t *ctx, const xfr_primary_t *p, struct sockaddr_storage *master_addr, int family, uint8_t ext_ver,
                       bool ext_probe, tsig_key_t *tsig_key, uint32_t ixfr_serial, axfr_session_t *session) {
  uint32_t active_serial = ctx->entry ? ctx->entry->serial : 0;
  memset(session, 0, sizeof(*session));
  session->query_id = (uint16_t)(arc4random() & 0xFFFF);
  session->query_type = ixfr_serial ? 251 : 252;
  session->is_ixfr = ixfr_serial != 0;
  /* AXFR に切り替えたときも、手元より古い版は受け取らない (parse_xfr_packet() のロールバック検査) */
  session->client_serial = active_serial;
  session->max_records = ctx->max_records;         /* I2: the limits of the zone (max-zone-records / max-zone-bytes) */
  session->max_bytes = ctx->max_bytes;
  session->eff = ctx->has_eff ? &ctx->eff : NULL;                        /* batch 4: the timers are held to min/max-refresh/retry-time */
  session->idle_secs = ctx->has_eff ? ctx->eff.xfer_idle_in : 0;      /* max-transfer-idle-in (0 = no limit) */
  session->deadline = ctx->has_eff && ctx->eff.xfer_time_in ? time(NULL) + (time_t)ctx->eff.xfer_time_in : 0; /* max-transfer-time-in */

  int tcp_fd = xfr_connect(ctx, p, master_addr, family);
  if (tcp_fd < 0) return -1;
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
  session->ext_probe = ext_probe;
  size_t req_len = build_xfr_request(axfr_req, sizeof(axfr_req), ctx->domain, ixfr_serial, session->query_id, ext_ver,
                                     ctx_request_expire(ctx, p), false, tsig_key, req_mac, &req_mac_len, p);
  if (req_len == 0) {
    syslog(LOG_ERR, "[AXFR] Failed to build%s request for zone %s", tsig_key ? " TSIG-signed" : "", ctx->domain);
  } else if (send(tcp_fd, axfr_req, req_len, 0) == (ssize_t)req_len) {
    // handle_axfr_event() は writer_lock を持ったまま読み取り区間に入るので、先にスロットを確保する
    rcu_aux_thread_pin();
    axfr_res = handle_axfr_event(tcp_fd, ctx->entry, stream_ctx, session, tsig_key,
                                 req_mac_len > 0 ? req_mac : NULL, req_mac_len);
    rcu_aux_thread_unpin();
  } else {
    syslog(LOG_ERR, "[AXFR] Failed to send request for zone %s to %s", ctx->domain, p->ip);
  }
  free(stream_ctx);
  close(tcp_fd);
  return axfr_res;
}

uint8_t xfr_ext_effective(uint8_t state, time_t set_at, time_t now) {
  if ((state == XFR_EXT_STANDARD || state == XFR_EXT_V2) && now - set_at > XFR_EXT_REPROBE_SECS) return XFR_EXT_UNKNOWN;
  return state;
}

uint8_t xfr_ext_request_version(uint8_t state) { return state == XFR_EXT_V2 ? 2 : KARIDNS_EXT_VERSION; }

bool xfr_ext_probe(uint8_t state) { return state == XFR_EXT_UNKNOWN || state == XFR_EXT_V3; }

uint8_t xfr_ext_learn(bool answered_extended, uint8_t answered_version) {
  if (!answered_extended) return XFR_EXT_STANDARD;
  return answered_version >= 3 ? XFR_EXT_V3 : XFR_EXT_V2;
}

/* The refresh of one primary: everything the thread did for the single primary before batch 4.  Returns an XFR_R_* code. */
static int xfr_try_primary(void *arg, int idx) {
  axfr_bg_ctx_t *ctx = (axfr_bg_ctx_t *)arg;
  const xfr_primary_t *p = &ctx->prim[idx];
  /* [H-4] p->has_tsig が真の場合は、p 内に値コピーされた TSIG 情報から
   * スタック上の tsig_key_t を組み立てて使用する (config ポインタを参照しない)。*/
  tsig_key_t local_tsig_key;
  tsig_key_t *tsig_key_ptr = NULL;
  if (p->has_tsig) {
    memset(&local_tsig_key, 0, sizeof(local_tsig_key));
    local_tsig_key.name = (char *)p->tsig_name;
    local_tsig_key.algorithm = (char *)p->tsig_algorithm;
    local_tsig_key.secret = NULL; /* 使用しないので NULL 可 */
    memcpy(local_tsig_key.secret_decoded, p->tsig_secret_decoded, p->tsig_secret_decoded_len);
    local_tsig_key.secret_decoded_len = p->tsig_secret_decoded_len;
    local_tsig_key.next = NULL;
    tsig_key_ptr = &local_tsig_key;
  }
  struct sockaddr_storage master_addr;
  memset(&master_addr, 0, sizeof(master_addr));
  int domain_family = AF_INET;
  if (inet_pton(AF_INET, p->ip, &((struct sockaddr_in *)&master_addr)->sin_addr) == 1) {
    domain_family = AF_INET;
    master_addr.ss_family = AF_INET;
    ((struct sockaddr_in *)&master_addr)->sin_port = htons(p->port > 0 ? p->port : 53);
  } else if (inet_pton(AF_INET6, p->ip, &((struct sockaddr_in6 *)&master_addr)->sin6_addr) == 1) {
    domain_family = AF_INET6;
    master_addr.ss_family = AF_INET6;
    ((struct sockaddr_in6 *)&master_addr)->sin6_port = htons(p->port > 0 ? p->port : 53);
  } else {
    syslog(LOG_ERR, "[AXFR] Invalid master IP address format: '%s'", p->ip);
    return XFR_R_FAILED;
  }
  /* transfers-per-ns (the `transfers` of the primary's server statement replaces it): a primary that already serves that many transfers to us is asked
   * later (BIND queues the zone) */
  uint32_t per_ns = p->per_ns_set ? p->per_ns : ctx->per_ns_limit;
  if (!xfr_ns_acquire(&master_addr, ctx->has_eff ? per_ns : UINT32_MAX)) {
    syslog(LOG_INFO, "[AXFR] zone %s: transfer from %s deferred due to quota (%s %u)", ctx->domain, p->ip, p->per_ns_set ? "transfers of the server statement" : "transfers-per-ns", per_ns);
    return XFR_R_DEFERRED;
  }

  axfr_session_t session;
  memset(&session, 0, sizeof(session));
  session.eff = ctx->has_eff ? &ctx->eff : NULL;   /* the SOA probe's up-to-date answer holds the timers to the limits as well */
  uint32_t active_serial = ctx->entry ? ctx->entry->serial : 0;
  int axfr_res;
  bool probed_newer = false;
  if (!ctx_request_ixfr(ctx, p) && active_serial != 0) {
    /* request-ixfr no: SOA first, and the AXFR only when the primary is ahead */
    int pr = xfr_soa_probe(ctx, p, &master_addr, domain_family, tsig_key_ptr, active_serial, &session);
    if (pr == XFR_R_UPTODATE) {
      pthread_mutex_lock(&ctx->entry->writer_lock);
      xfr_note_uptodate(ctx->entry, &session);
      pthread_mutex_unlock(&ctx->entry->writer_lock);
      xfr_ns_release(&master_addr);
      return XFR_R_UPTODATE;
    }
    if (pr == XFR_R_BEHIND) {
      session.serial_behind = true;
      if (!ctx_multi_master(ctx))
        syslog(LOG_INFO, "[AXFR] zone %s: serial number (%u) received from primary %s < ours (%u)", ctx->domain, session.initial_soa_serial, p->ip,
               active_serial);
      xfr_ns_release(&master_addr);
      return XFR_R_BEHIND;
    }
    if (pr == XFR_R_FAILED) {
      xfr_ns_release(&master_addr);
      return XFR_R_FAILED;
    }
    probed_newer = true;
  }
  /* B8t-2: the Extended AXFR version this primary speaks (kept per zone, in memory): ask for version 3 first; when a standard transfer
   * comes back, ask once more with version 2 and remember what the primary did (xfr_ext_*) */
  time_t ext_now = time(NULL);
  uint8_t ext_state = ctx->entry ? xfr_ext_effective(ctx->entry->xfr_ext_state, ctx->entry->xfr_ext_set, ext_now) : XFR_EXT_UNKNOWN;
  uint8_t ext_ver = p->no_edns ? 0 : xfr_ext_request_version(ext_state);   /* edns no: no OPT, so no Extended AXFR either */
  uint32_t ixfr_serial = probed_newer ? 0 : active_serial;   /* the SOA said the primary is ahead: the whole zone (request-ixfr no) */
  axfr_res = xfr_attempt(ctx, p, &master_addr, domain_family, ext_ver, ext_ver && xfr_ext_probe(ext_state), tsig_key_ptr, ixfr_serial, &session);
  if (axfr_res < 0 && session.no_ext_answer) {
    syslog(LOG_NOTICE, "[AXFR] zone %s: %s answered a version 3 request with a standard transfer; asking with version 2", ctx->domain, p->ip);
    ext_ver = 2;
    axfr_res = xfr_attempt(ctx, p, &master_addr, domain_family, ext_ver, false, tsig_key_ptr, ixfr_serial, &session);
  }
  /* R-19, RFC 1995 §4: IXFR を扱えないプライマリ (FORMERR / NOTIMP) からは AXFR で1回だけ取り直す。
   * I1: 差分列が手元の版から始まらない (または連続しない) IXFR も同じ (RFC 1995 §4、parse_xfr_packet()) */
  if (axfr_res < 0 && ixfr_serial != 0 && (session.rcode == 1 || session.rcode == 4 || session.ixfr_bad_sequence)) {
    syslog(LOG_NOTICE, "[AXFR] zone %s: %s %s, retrying with AXFR", ctx->domain, p->ip,
           session.ixfr_bad_sequence ? "sent an IXFR whose difference sequences do not start from our serial" : "does not support IXFR");
    axfr_res = xfr_attempt(ctx, p, &master_addr, domain_family, ext_ver, false, tsig_key_ptr, 0, &session);
  }
  xfr_ns_release(&master_addr);
  if (axfr_res > 0 && ctx->entry && !p->no_edns) {   /* edns no asked for nothing, so the answer says nothing about the primary */
    uint8_t learned = xfr_ext_learn(session.is_extended_mode, session.ext_version);
    if (learned != ctx->entry->xfr_ext_state || ext_state != ctx->entry->xfr_ext_state) {
      if (learned == XFR_EXT_V2)
        syslog(LOG_NOTICE, "[AXFR] zone %s: the primary %s speaks Extended AXFR version 2 only; version 3 is tried again after %d hours",
               ctx->domain, p->ip, XFR_EXT_REPROBE_SECS / 3600);
      ctx->entry->xfr_ext_state = learned;
      ctx->entry->xfr_ext_set = ext_now;       /* the re-probe time counts from the change */
    }
  }
  if (session.out_of_zone_skipped > 0) {
    syslog(LOG_WARNING, "[AXFR] zone %s: ignored %u out-of-zone record(s) sent by %s", ctx->domain, session.out_of_zone_skipped, p->ip);
  }
  if (axfr_res == 1) {
    syslog(LOG_NOTICE, "[AXFR] Successfully transferred zone %s from %s", ctx->domain, p->ip);
    return XFR_R_TRANSFERRED;
  }
  if (axfr_res == 2) {
    // Zone is up to date. Do not log to avoid spam on short refresh intervals.
    return XFR_R_UPTODATE;
  }
  if (session.serial_behind) {
    /* BIND zone.c refresh_callback(): logged unless multi-master; either way the next primary is asked */
    if (!ctx_multi_master(ctx))
      syslog(LOG_INFO, "[AXFR] zone %s: serial number (%u) received from primary %s < ours (%u)", ctx->domain, session.initial_soa_serial, p->ip,
             active_serial);
    return XFR_R_BEHIND;
  }
  syslog(LOG_ERR, "[AXFR] Failed to transfer zone %s from %s", ctx->domain, p->ip);
  return XFR_R_FAILED;
}

void *axfr_bg_thread_func(void *arg) {
  atomic_fetch_add_explicit(&g_xfers_running, 1, memory_order_relaxed);
  axfr_bg_ctx_t *ctx = (axfr_bg_ctx_t *)arg;
  zone_db_snapshot_t *bg_snap = ctx->snap;
  /* the primaries in order (BIND refresh_callback(): the next one is asked after a failure, an up-to-date answer or a primary that is behind;
   * a transfer ends the refresh) */
  xfr_run_t run;
  xfr_run_primaries(ctx->nprim, xfr_try_primary, ctx, &run);
  if (ctx->entry) {
    if (run.tried == 0 && run.deferred > 0) {
      /* every primary was at its transfers-per-ns quota: look again at the next tick instead of waiting for the retry time */
      atomic_store_explicit(&ctx->entry->next_check, time(NULL) + 1, memory_order_release);
    }
    atomic_store_explicit(&ctx->entry->is_transferring, false, memory_order_release);
  }
  free(ctx);
  if (bg_snap)
    release_zone_snapshot(bg_snap);
  /* the scheduler (the control thread) took the slot before it started this thread; a caller that did not (a unit test) must not drive the count negative */
  if (atomic_fetch_sub_explicit(&g_xfr_in_active, 1, memory_order_acq_rel) <= 0) atomic_store_explicit(&g_xfr_in_active, 0, memory_order_release);
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
  const zone_image_view_t *view; /* B8t-1: a standard AXFR carries the requester's view: the RRs it does not see are left out (NULL = no filtering) */
  xext_t xe;            /* Extended AXFR: the one encoder of the extension records (dns_wire.h), state markers included */
  bool wrap_apex_soa;   /* B8t-2 (v3, several or restricted SOA RRs): every apex SOA RR of the body is a 65406 wrapper */
  bool one_answer;      /* batch 5: the server statement of the requester says `transfer-format one-answer`: one RR in every message (BIND xfrout.c, RFC 5936 §2.2 allows it) */
} axfr_emit_ctx_t;

/* One RR to send: a builder record (IXFR history, KariDNS markers) or RR `rr` of a zone image (S5 B-2: the zone itself) */
static int axfr_write_item(axfr_emit_ctx_t *ec, const dns_record_t *rec, const zone_image_t *img, uint32_t rr) {
  if (img) {
    uint32_t ttl = zone_image_rr_ttl(img, rr);
    /* as axfrdns does (behavioural reference, djbdns 1.05): a tinydns countdown RR (TTL 0 with a time stamp) is sent with TTL 2 */
    const zone_image_ext_t *ext = ec->view ? zone_image_rr_ext(img, rr) : NULL;
    if (ext && ext->ttd != 0 && (ext->flags & ZONE_IMAGE_EXT_COUNTDOWN)) ttl = 2;
    return image_serialize_rr(img, rr, ec->res, KARIDNS_AXFR_MSG_LIMIT, &ec->offset, &ec->comp_ctx, NULL, ttl);
  }
  return serialize_dns_record(ec->res, KARIDNS_AXFR_MSG_LIMIT, &ec->offset, rec, &ec->comp_ctx, NULL, 0xFFFFFFFF);
}

static int axfr_emit_item(axfr_emit_ctx_t *ec, const dns_record_t *rec, const zone_image_t *img, uint32_t rr) {
  uint16_t prev_offset = ec->offset;
  if ((ec->one_answer && ec->answers > 0) || axfr_write_item(ec, rec, img, rr) < 0) {   /* the message is full, or (one-answer) holds its RR already */
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
      kdns_logc(LOGC_XFER_OUT, LOG_ERR, "[AXFR] Record too large to fit in any TCP message (name=%s type=%u), aborting transfer",
             img ? zone_image_name_text(img, zone_image_rr_name(img, rr)) : (rec->name ? rec->name : "(null)"),
             img ? zone_image_rr_type(img, rr) : rec->type_code);
      return -1;
    }
  }
  ec->answers++;
  return 0;
}

static int axfr_emit_record(axfr_emit_ctx_t *ec, const dns_record_t *rec) { return axfr_emit_item(ec, rec, NULL, 0); }

/* the output of xext_t: the records go into the message stream like any other */
static int axfr_xext_emit(void *ud, const dns_record_t *rec) { return axfr_emit_record((axfr_emit_ctx_t *)ud, rec); }

/* A zone RR (builder record of the IXFR history, or image RR) with the Extended AXFR state markers around it */
static int axfr_emit_zone_item(axfr_emit_ctx_t *ec, const dns_record_t *rec_item, const zone_image_t *img, uint32_t rr) {
  const zone_image_ext_t *ext = img ? zone_image_rr_ext(img, rr) : NULL;
  const char *item_loc_tag = img ? (ext ? zone_image_str(img, ext->loc_tag_off) : NULL) : rec_item->bind_location_tag;
  const char *item_ecs_tag = img ? (ext ? zone_image_str(img, ext->ecs_tag_off) : NULL) : rec_item->ecs_subnet_tag;
  const char *item_tloc = img ? (ext ? ext->loc : "\0") : rec_item->tinydns_loc;
  int64_t item_ttd = img ? (ext ? ext->ttd : 0) : (int64_t)rec_item->tinydns_ttd;
  if (!ec->is_extended_axfr) {
    /* B8t-1: a standard AXFR is the zone as the requester sees it now (axfrdns.c: the location of the client, the time stamps of
     * now); a record it does not see is not sent. Locations and tags are not sent: the requester has no use for them. */
    if (ec->view && img) {
      uint32_t ttl;
      if (!zone_image_rr_visible(img, rr, ec->view, &ttl)) return 0;
      return axfr_emit_item(ec, rec_item, img, rr);
    }
    if (item_loc_tag != NULL || item_ecs_tag != NULL || item_tloc[0] != 0 || item_tloc[1] != 0 || item_ttd != 0) {
      /* Skip tagged records in fallback mode */
      return 0;
    }
    return axfr_emit_item(ec, rec_item, img, rr);
  }

  if (xext_select(&ec->xe, item_loc_tag, item_ecs_tag) < 0) return -1;
  if (xext_rr_is_tinydns(item_tloc, item_ttd) ||
      (ec->wrap_apex_soa && img && zone_image_rr_type(img, rr) == 6 && zone_image_rr_name(img, rr) == img->apex_name)) {
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

static int axfr_emit_zone_record(axfr_emit_ctx_t *ec, const dns_record_t *rec_item) {
  return axfr_emit_zone_item(ec, rec_item, NULL, 0);
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
static bool zone_has_multiple_or_restricted_soa(const zone_image_t *img);

static bool zone_needs_extended_axfr(const zone_image_t *zone, const zone_db_entry_t *entry, uint8_t ext_ver) {
  if (zone_image_has_zattr(zone) || (zone->flags & (ZONE_IMAGE_F_TINYDNS | ZONE_IMAGE_F_SOA_ATTR)) ||
      zone_has_multiple_or_restricted_soa(zone))
    return true;
  /* version 3 sends the settings (and so the trusted resolvers of the configuration) with an IXFR as well */
  if (ext_ver >= 3) return false;
  bool cfg_trusted = false;
  server_config_t *cfg = acquire_config_snapshot();
  if (cfg) {
    const zone_config_t *zcfg = zone_entry_config(cfg, entry);
    cfg_trusted = (zcfg && zext(zcfg)->ecs_trusted_resolvers_count > 0) || cfg->ecs_trusted_resolvers_count > 0;
    release_config_snapshot(cfg);
  }
  return cfg_trusted;
}

/* B8t-1: the apex has more than one SOA RR, or one that some client does not see */
static bool zone_has_multiple_or_restricted_soa(const zone_image_t *img) {
  if (img->flags & ZONE_IMAGE_F_SOA_ATTR) return true;
  if (img->apex_name == ZONE_IMAGE_NONE) return false;
  uint32_t k = zone_image_rrset_next(img, img->apex_name, 6, zone_image_name_first_rr(img, img->apex_name));
  return k != ZONE_IMAGE_NONE && zone_image_rrset_next(img, img->apex_name, 6, k + 1) != ZONE_IMAGE_NONE;
}

/* B8t-2 (v3): the settings of the zone as this server applies them, as a TYPE 65408 record; nothing when there are none.  A zone
 * whose data carries its own trusted resolvers does not repeat them.  A text that does not fit the record is not sent (logged). */
static int axfr_emit_settings(axfr_emit_ctx_t *ec, const zone_db_entry_t *entry, bool omit_trusted) {
  char *text = malloc(KARIDNS_SETTINGS_MAX + 1);
  if (!text) return -1;
  rcu_aux_read_lock();
  server_config_t *cfg = acquire_config_snapshot();
  size_t len = 0;
  if (cfg) len = zone_settings_render(cfg, zone_entry_config(cfg, entry), omit_trusted, text, KARIDNS_SETTINGS_MAX + 1);
  if (cfg) release_config_snapshot(cfg);
  rcu_aux_read_unlock();
  int rc = 0;
  if (len == (size_t)-1)
    kdns_logc(LOGC_XFER_OUT, LOG_WARNING, "[AXFR] zone '%s': the settings of the zone are longer than %u octets and are not sent", entry->domain, KARIDNS_SETTINGS_MAX);
  else if (len > 0)
    rc = xext_emit_settings(&ec->xe, text, len);
  free(text);
  return rc;
}

/* B8t-2 (v3): the tag definitions of the configuration (the zone's location-tags / ecs-tags, else options') that the RRs of a zone
 * use, when the zone data defines no tags of that kind itself (the data's own definitions are the only ones used then, as when the
 * zone is served): sent as tag definitions, so that the secondary resolves the tags as the primary does */
static int axfr_emit_config_tags(axfr_emit_ctx_t *ec, const zone_image_t *img, const zone_db_entry_t *entry, const zone_arena_t *zattr) {
  bool want_loc = zattr->bind_location_tag_count == 0, want_ecs = zattr->bind_ecs_tag_count == 0;
  if (!want_loc && !want_ecs) return 0;
  uint32_t used_loc[256], used_ecs[256];
  int nloc = 0, necs = 0;
  for (uint32_t rr = 0; rr < img->n_rrs; rr++) {
    const zone_image_ext_t *e = zone_image_rr_ext(img, rr);
    if (!e) continue;
    if (want_loc && e->loc_tag_off != 0) {
      int i = 0;
      while (i < nloc && used_loc[i] != e->loc_tag_off) i++;
      if (i == nloc && nloc < 256) used_loc[nloc++] = e->loc_tag_off;
    }
    if (want_ecs && e->ecs_tag_off != 0) {
      int i = 0;
      while (i < necs && used_ecs[i] != e->ecs_tag_off) i++;
      if (i == necs && necs < 256) used_ecs[necs++] = e->ecs_tag_off;
    }
  }
  if (nloc == 0 && necs == 0) return 0;
  int rc = 0;
  rcu_aux_read_lock();
  server_config_t *cfg = acquire_config_snapshot();
  const zone_config_t *zcfg = cfg ? zone_entry_config(cfg, entry) : NULL;
  for (int kind = 0; kind < 2 && rc == 0 && cfg; kind++) {
    const ecs_tag_def_t *defs;
    int ndef;
    if (kind == 0) {
      if (nloc == 0) continue;
      defs = (zcfg && zext(zcfg)->location_tags) ? zext(zcfg)->location_tags : cfg->location_tags;
      ndef = (zcfg && zext(zcfg)->location_tags) ? zext(zcfg)->location_tag_count : cfg->location_tag_count;
    } else {
      if (necs == 0) continue;
      defs = (zcfg && zext(zcfg)->ecs_tags) ? zext(zcfg)->ecs_tags : cfg->ecs_tags;
      ndef = (zcfg && zext(zcfg)->ecs_tags) ? zext(zcfg)->ecs_tag_count : cfg->ecs_tag_count;
    }
    for (int d = 0; d < ndef && rc == 0; d++) {
      const uint32_t *used = kind == 0 ? used_loc : used_ecs;
      int nused = kind == 0 ? nloc : necs;
      bool uses = false;
      for (int u = 0; u < nused && !uses; u++) uses = defs[d].tag && strcasecmp(defs[d].tag, zone_image_str(img, used[u])) == 0;
      if (uses && xext_emit_tagdef(&ec->xe, kind == 1, &defs[d]) < 0) rc = -1;
    }
  }
  if (cfg) release_config_snapshot(cfg);
  rcu_aux_read_unlock();
  return rc;
}

/* The message under construction: the header and question of the request, QR=1 AA=1 (R-05), no RRs yet.  The caller sets what is particular to it (the
 * view, the extension encoder, one-answer ...) after the call. */
static void axfr_ec_start(axfr_emit_ctx_t *ec, uint8_t *res, const uint8_t *req, size_t q_offset, int client_fd, bool is_extended_axfr,
                          tsig_key_t *tsig_key, const uint8_t *req_mac, size_t req_mac_len, const edns_info_t *resp_edns,
                          const struct sockaddr_storage *client_addr, socklen_t client_len, const struct sockaddr_storage *server_addr,
                          bool has_server_addr, const char *domain) {
  memset(ec, 0, sizeof(*ec));
  ec->res = res;
  ec->offset = (uint16_t)q_offset;
  ec->q_offset = (uint16_t)q_offset;
  ec->answers = 0;
  ec->req = req;
  ec->client_fd = client_fd;
  ec->is_extended_axfr = is_extended_axfr;
  ec->send_opt = resp_edns->present;
  ec->opt_sent = false;
  ec->is_subsequent = false;
  ec->tsig_key = tsig_key;
  if (req_mac_len > 0) {
    memcpy(ec->tsig_mac, req_mac, req_mac_len);
    ec->tsig_mac_len = req_mac_len;
  }
  ec->resp_edns = *resp_edns;
  ec->client_addr = client_addr;
  ec->client_len = client_len;
  ec->server_addr = server_addr;
  ec->has_server_addr = has_server_addr;
  ec->domain = domain;
  memset(res, 0, 65535);
  memcpy(res, req, q_offset);
  dns_init_response_header(res, req, 0, true); /* QR=1 AA=1、RA/Z/AD/TC は写さない (R-05) */
  res[8] = 0;
  res[9] = 0;
  res[10] = 0;
  res[11] = 0;
  compress_ctx_init_packet(&ec->comp_ctx);
  register_wire_name_for_compression(res, DNS_HEADER_SIZE, &ec->comp_ctx);
}

/* The last message of the transfer (the RRs not sent yet), with the OPT of the first message when none went out, signed and sent.  0, or -1: a failure. */
static int axfr_ec_finish(axfr_emit_ctx_t *ec) {
  if (ec->answers == 0) return 0;
  ec->res[6] = (uint8_t)(ec->answers >> 8);
  ec->res[7] = (uint8_t)(ec->answers & 0xFF);
  if (ec->send_opt && !ec->opt_sent) {
    uint16_t arcount = 0;
    assemble_edns_opt(ec->res, 65535, &ec->offset, &arcount, &ec->resp_edns, 0, true, NULL);
    ec->res[10] = (arcount >> 8) & 0xFF;
    ec->res[11] = arcount & 0xFF;
    ec->opt_sent = true;
  }
  if (ec->tsig_key) {
    size_t sign_len = ec->offset;
    if (tsig_sign_packet(ec->res, &sign_len, 65535, ec->tsig_key, 0, ec->tsig_mac, &ec->tsig_mac_len, NULL, 0, ec->is_subsequent) != 0) return -1;
    ec->offset = (uint16_t)sign_len;
  }
  write_dnstap_event(NULL, 2 /*AUTH_RESPONSE*/, ec->res, ec->offset, (const struct sockaddr *)ec->client_addr, ec->client_len,
                     ec->has_server_addr ? (const struct sockaddr *)ec->server_addr : NULL, ec->has_server_addr, IPPROTO_TCP);
  return send_tcp_dns_message(ec->client_fd, ec->res, ec->offset) < 0 ? -1 : 0; /* RFC 7766 §8 */
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
  uint8_t ext_ver = 0; /* B8t-2: the version of the stream: what the requester speaks, if it is 2 or 3 */
  if (parse_edns_opt(req, req_len, req_qd, req_an, req_ns, req_ar, &req_edns) == 0) {
    if (req_edns.has_karidns_ext && KARIDNS_EXT_VERSION_OK(req_edns.karidns_ext_version)) {
      uint32_t exp_hash = calc_fnv1a_str(entry->domain);
      if (req_edns.karidns_ext_hash == exp_hash) {
        is_extended_axfr = true;
        ext_ver = req_edns.karidns_ext_version;
      }
    }
  }
  const bool v3 = is_extended_axfr && ext_ver >= 3;
  edns_info_t resp_edns = {0};
  /* R-16, RFC 5936 §2.2.5: 要求に OPT があれば最初のメッセージに OPT を1つ付ける */
  if (req_edns.present) resp_edns.present = true;
  if (is_extended_axfr) {
    resp_edns.present = true;
    resp_edns.has_karidns_ext = true;
    resp_edns.karidns_ext_version = ext_ver;
    resp_edns.karidns_ext_hash = calc_fnv1a_str(entry->domain);
  }
  /* RFC 7314 §3: EXPIRE 付きの AXFR/IXFR には SOA EXPIRE (プライマリ) または
   * expire タイマーの残り (セカンダリ) を最初のメッセージの OPT で返す。 */
  if (req_edns.has_expire_query) {
    resp_edns.present = true;
    resp_edns.send_expire = true;
    resp_edns.send_expire_value = zone_expire_option_value(entry, time(NULL));
  }

  uint32_t soa_rr = zone_image_apex_soa(current_zone); /* the reference SOA: serial, the frame of an Extended AXFR */
  if (soa_rr == ZONE_IMAGE_NONE) {
    free(res);
    return;
  }

  /* An Extended AXFR of version 2 cannot carry several or restricted SOA RRs (the frame SOA has no attributes, and the receiver
   * ends the transfer at a second SOA).  Sending such a secondary the reference SOA alone would change what it serves (a hidden
   * SOA would become visible to everybody), so it is refused, as it was by B8t-1; version 3 carries the SOA set (SOA_SET).  A
   * standard AXFR is unaffected. */
  const bool soa_multi = zone_has_multiple_or_restricted_soa(current_zone);
  if (is_extended_axfr && !v3 && soa_multi) {
    kdns_logc(LOGC_XFER_OUT, LOG_WARNING, "[AXFR] zone '%s': Extended AXFR refused: the zone has several or restricted SOA records "
           "(location, time stamp, tag) and the requester speaks version 2 of the extended format, which cannot carry them "
           "(upgrade the secondary)", entry->domain);
    free(res);
    axfr_send_error(client_fd, req, req_len, 5, false, 0, "Extended transfer (version 2) of a zone with several or restricted SOA records is not supported; use version 3",
                    tsig_key, req_mac, req_mac_len, client_addr, client_len, server_addr, has_server_addr);
    return;
  }

  /* B8t-1: a standard AXFR of a zone with per-client RRs (tinydns locations and time stamps, $LOCATION / $ECS-SUBNET tags) is the zone
   * as the requester sees it now (axfrdns.c): the RRs it does not see are not sent, the opening and closing SOA is the first
   * SOA it sees, and a requester that sees no SOA is refused (REFUSED, EDE 18 Prohibited; RFC 8914 §4.19, as BIND answers a
   * client the zone is not served to). An ECS tag is never matched (a transfer has no client subnet). A zone without such
   * RRs is sent as before. */
  zone_image_view_t xview = { {0, 0}, NULL, NULL, 0 };
  uint32_t frame_rr = soa_rr;
  if (!is_extended_axfr && (current_zone->flags & ZONE_IMAGE_F_VIEW)) {
    char cip[INET6_ADDRSTRLEN] = "";
    if (client_addr && client_addr->ss_family == AF_INET)
      inet_ntop(AF_INET, &((const struct sockaddr_in *)client_addr)->sin_addr, cip, sizeof(cip));
    else if (client_addr && client_addr->ss_family == AF_INET6)
      inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)client_addr)->sin6_addr, cip, sizeof(cip));
    server_config_t *vcfg = acquire_config_snapshot();
    const zone_config_t *vzcfg = vcfg ? zone_entry_config(vcfg, entry) : NULL;
    zone_client_view(current_zone, vcfg, vzcfg, cip, false, NULL, 0, &xview, NULL);
    if (vcfg) release_config_snapshot(vcfg);
    frame_rr = zone_image_visible_soa(current_zone, &xview, NULL);
    if (frame_rr == ZONE_IMAGE_NONE) {
      free(res);
      axfr_send_error(client_fd, req, req_len, 5, false, 18, "Transfer refused: the zone is not served to this client", tsig_key,
                      req_mac, req_mac_len, client_addr, client_len, server_addr, has_server_addr);
      return;
    }
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

  /* The `server` statement that covers the requester (batch 5; the view's, else the top-level ones) can say provide-ixfr (it replaces the
   * zone's, view's and options' value for this client: BIND xfrout.c) and transfer-format one-answer. */
  bool one_answer = false;
  bool provide_ixfr = true;
  {
    server_config_t *pcfg = acquire_config_snapshot();
    const server_stmt_t *srv = config_server_find_sa(pcfg, entry->view_name, (const struct sockaddr *)client_addr);
    one_answer = srv && (srv->set & SV_TRANSFER_FORMAT) && (srv->bools & SV_B_ONE_ANSWER);
    if (is_ixfr) {
      xfr_eff_t pe;
      xfr_opts_effective_peer(pcfg, pcfg ? zone_entry_config(pcfg, entry) : NULL, entry->view_name, srv, &pe);
      provide_ixfr = pe.provide_ixfr;
    }
    if (pcfg) release_config_snapshot(pcfg);
  }
  /* R-15, RFC 1995 §2: 同じか新しい版 (RFC 1982 の比較) を持つクライアントには現在の SOA 1件で答える。BIND 9.20 lib/ns/xfrout.c ns_xfr_start():
   * this test (DNS_SERIAL_GE, "is_poll") comes before the provide-ixfr check, so provide-ixfr no does not change the answer to a client that is
   * up to date. */
  bool client_up_to_date = is_ixfr && (client_serial == current_serial ||
                                       serial_is_newer(client_serial, current_serial));
  /* provide-ixfr no (BIND 9.20 ARM: "only responds with a full zone transfer (AXFR)"; xfrout.c "IXFR delta response disabled due to
   * 'provide-ixfr no;' being set", mnemonic "AXFR-style IXFR"): a client that is behind gets the whole zone, as with ixfr-history 0 (RFC 1995 §4
   * allows an AXFR-style answer to an IXFR request) */
  if (!provide_ixfr && !client_up_to_date) is_ixfr = false;
  /* X-24: 拡張を求める KariDNS セカンダリの IXFR は、拡張でしか運べないデータがあるときだけ
   * Extended AXFR にする。それ以外は通常の IXFR (差分が無ければ下で AXFR) で答える。 */
  if (is_extended_axfr && is_ixfr && !client_up_to_date && zone_needs_extended_axfr(current_zone, entry, ext_ver)) {
    is_ixfr = false;
  }
  /* B8t-1: the history of differences is not per client; a standard IXFR of a zone with per-client RRs gets the whole zone as the
   * requester sees it (RFC 1995 §4: the server may answer an IXFR with an AXFR). The up to date answer is the one SOA. */
  if (!is_extended_axfr && is_ixfr && !client_up_to_date && (current_zone->flags & ZONE_IMAGE_F_VIEW)) {
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
    /* B8t-2: the differences of a version that had several or restricted SOA RRs cannot say what happened to the SOA set (RFC 1995 §4
     * allows the whole zone instead) */
    bool soa_in_history = false;
    for (int t = 0; t < txn_count && !soa_in_history; t++) {
      int nsoa = 0;
      for (int i = 0; i < txn_list[t]->deleted_count; i++)
        if (txn_list[t]->deleted[i].type_code == 6 && (++nsoa > 1 || dns_record_is_restricted(&txn_list[t]->deleted[i]))) soa_in_history = true;
      nsoa = 0;
      for (int i = 0; i < txn_list[t]->added_count; i++)
        if (txn_list[t]->added[i].type_code == 6 && (++nsoa > 1 || dns_record_is_restricted(&txn_list[t]->added[i]))) soa_in_history = true;
    }
    if (soa_in_history) {
      for (int t = 0; t < txn_count; t++)
        if (atomic_fetch_sub_explicit(&txn_list[t]->ref_count, 1, memory_order_acq_rel) == 1) free_ixfr_txn(txn_list[t]);
      txn_count = 0;
      send_ixfr = false;
    }
  }

  axfr_emit_ctx_t ec;
  axfr_ec_start(&ec, res, req, q_offset, client_fd, is_extended_axfr, tsig_key, req_mac, req_mac_len, &resp_edns, client_addr, client_len,
                server_addr, has_server_addr, entry->domain);
  ec.view = (!is_extended_axfr && (current_zone->flags & ZONE_IMAGE_F_VIEW)) ? &xview : NULL;
  xext_init(&ec.xe, entry->domain, axfr_xext_emit, &ec);
  ec.wrap_apex_soa = v3 && soa_multi && !send_ixfr;
  ec.one_answer = one_answer;

  if (!send_ixfr && is_extended_axfr && zone_image_zattr_load(current_zone, &zattr) != 0) goto axfr_error;
  if (send_ixfr) {
    if (axfr_emit_item(&ec, NULL, current_zone, frame_rr) < 0) goto axfr_error;
    if (v3 && txn_count > 0 && axfr_emit_settings(&ec, entry, zattr.bind_ecs_trusted_resolver_count > 0) < 0) goto axfr_error;
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
        if (axfr_emit_zone_record(&ec, &txn->deleted[i]) < 0) goto axfr_error;
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
        if (axfr_emit_zone_record(&ec, &txn->added[i]) < 0) goto axfr_error;
      }
    }
    if (txn_count > 0) {
      if (axfr_emit_item(&ec, NULL, current_zone, frame_rr) < 0) goto axfr_error;
    }
  } else {
    // 1. Initial SOA
    if (axfr_emit_item(&ec, NULL, current_zone, frame_rr) < 0) goto axfr_error;

    // Definitions emitted after first SOA in extended mode
    if (is_extended_axfr) {
      if (v3 && soa_multi) {
        /* the apex SOA RRs are body RRs; the frame (the reference SOA) is not zone data */
        uint16_t nsoa = 0;
        uint32_t k = zone_image_rrset_next(current_zone, current_zone->apex_name, 6, zone_image_name_first_rr(current_zone, current_zone->apex_name));
        for (; k != ZONE_IMAGE_NONE && nsoa < 0xFFFF; k = zone_image_rrset_next(current_zone, current_zone->apex_name, 6, k + 1)) nsoa++;
        if (xext_emit_soa_set(&ec.xe, nsoa) < 0) goto axfr_error;
      }
      if (v3 && axfr_emit_settings(&ec, entry, zattr.bind_ecs_trusted_resolver_count > 0) < 0) goto axfr_error;
      for (int i = 0; i < zattr.bind_location_tag_count; i++)
        if (xext_emit_tagdef(&ec.xe, false, &zattr.bind_location_tags[i]) < 0) goto axfr_error;
      for (int i = 0; i < zattr.bind_ecs_tag_count; i++)
        if (xext_emit_tagdef(&ec.xe, true, &zattr.bind_ecs_tags[i]) < 0) goto axfr_error;
      if (v3 && axfr_emit_config_tags(&ec, current_zone, entry, &zattr) < 0) goto axfr_error;
      server_config_t *axfr_cfg = acquire_config_snapshot();
      const zone_config_t *axfr_zcfg = axfr_cfg ? zone_entry_config(axfr_cfg, entry) : NULL;
      char **trusted_res = (zattr.bind_ecs_trusted_resolver_count > 0 && zattr.bind_ecs_trusted_resolvers)
                            ? zattr.bind_ecs_trusted_resolvers : NULL;
      int trusted_count = trusted_res ? zattr.bind_ecs_trusted_resolver_count : 0;
      if (!trusted_res && !v3) {
        trusted_res = (axfr_zcfg && zext(axfr_zcfg)->ecs_trusted_resolvers) ? zext(axfr_zcfg)->ecs_trusted_resolvers
                                                                       : (axfr_cfg ? axfr_cfg->ecs_trusted_resolvers : NULL);
        trusted_count = (axfr_zcfg && zext(axfr_zcfg)->ecs_trusted_resolvers) ? zext(axfr_zcfg)->ecs_trusted_resolvers_count
                                                                   : (axfr_cfg ? axfr_cfg->ecs_trusted_resolvers_count : 0);
      }
      int trusted_rc = (trusted_count > 0 && trusted_res) ? xext_emit_trusted(&ec.xe, trusted_res, trusted_count) : 0;
      if (axfr_cfg) release_config_snapshot(axfr_cfg);
      if (trusted_rc < 0) goto axfr_error;
      for (int i = 0; i < zattr.location_count; i++) {
        const tinydns_location_entry_t *loc = &zattr.locations[i];
        if (xext_emit_locdef(&ec.xe, loc->code, loc->prefix_bits, loc->prefix) < 0) goto axfr_error;
      }
    }

    /* file order (zone_image_seq_rr), as the builder was walked before */
    for (uint32_t seq = 0; seq < current_zone->n_rrs; seq++) {
      uint32_t rr = zone_image_seq_rr(current_zone, seq);
      if (!ec.wrap_apex_soa && zone_image_rr_type(current_zone, rr) == 6 && zone_image_rr_name(current_zone, rr) == current_zone->apex_name) /* every apex SOA: the frame is the opening and closing SOA (B8t-1: axfrdns.c leaves SOA RRs out of the body); a version 3 SOA set is in the body instead */
        continue;
      if (axfr_emit_zone_item(&ec, NULL, current_zone, rr) < 0) goto axfr_error;
    }

    if (is_extended_axfr && xext_finish(&ec.xe) < 0) goto axfr_error;

    // 3. Trailing SOA
    if (axfr_emit_item(&ec, NULL, current_zone, frame_rr) < 0) goto axfr_error;
  }
  if (axfr_ec_finish(&ec) < 0) goto axfr_error;

  for (int t = 0; t < txn_count; t++) {
    if (atomic_fetch_sub_explicit(&txn_list[t]->ref_count, 1, memory_order_acq_rel) == 1) {
       free_ixfr_txn(txn_list[t]);
    }
  }
  if (res) free(res);
  xext_free(&ec.xe);
  zone_arena_destroy(&zattr);
  return;

axfr_error:
  xext_free(&ec.xe);
  zone_arena_destroy(&zattr);
  for (int t = 0; t < txn_count; t++) {
    if (atomic_fetch_sub_explicit(&txn_list[t]->ref_count, 1, memory_order_acq_rel) == 1) {
       free_ixfr_txn(txn_list[t]);
    }
  }
  if (res) free(res);
}

/* D1a step 7 (design 7, 12-6): an IXFR for a zone that is in the directory and not in memory, from a client that has the serial the directory has (or a
 * newer one, RFC 1982): the answer is the one current SOA (RFC 1995 §2: the server's version is not newer), and the zone is not read.  It is made from the
 * apex of the summary (the SOA, with the serial it describes), which the zone in memory would give with the same bytes: the same opening SOA, the OPT of
 * the first message (RFC 5936 §2.2.5, as send_axfr_response()), the RFC 7314 EXPIRE value, the KariDNS extension echo, and the TSIG of the request
 * (RFC 8945 §5.3).  A request without the client's SOA is a FORMERR (RFC 1995 §3), as for a zone in memory.  false: the answer needs the zone (not an IXFR,
 * no apex for the version the directory has, the client is behind): the caller waits for the zone. */
static bool axfr_send_up_to_date_from_apex(const axfr_worker_args_t *a, tsig_key_t *tsig_key) {
  if (a->qtype != 251 || !a->elem) return false;
  const zdir_apex_t *ap = atomic_load_explicit(&a->elem->apex, memory_order_acquire);
  if (!ap || ap->serial != zdir_serial(a->elem)) return false;
  size_t q_offset;
  if (skip_wire_name(a->req, a->req_len, DNS_HEADER_SIZE, &q_offset) != 0 || q_offset + 4 > a->req_len) return false;
  q_offset += 4;
  uint32_t client_serial = 0;
  if (!ixfr_request_client_serial(a->req, a->req_len, q_offset, &client_serial)) {
    axfr_send_error(a->client_fd, a->req, a->req_len, 1, false, 0xFFFF, NULL, tsig_key, a->tsig_mac, a->tsig_mac_len, &a->client_addr, a->client_len,
                    &a->server_addr, a->has_server_addr);
    return true;
  }
  if (!(client_serial == ap->serial || serial_is_newer(client_serial, ap->serial))) return false;
  edns_info_t req_edns = {0};
  edns_info_t resp_edns = {0};
  bool ext = false;
  if (parse_edns_opt(a->req, a->req_len, (uint16_t)((a->req[4] << 8) | a->req[5]), (uint16_t)((a->req[6] << 8) | a->req[7]),
                     (uint16_t)((a->req[8] << 8) | a->req[9]), (uint16_t)((a->req[10] << 8) | a->req[11]), &req_edns) == 0) {
    resp_edns.present = req_edns.present;
    if (req_edns.has_karidns_ext && KARIDNS_EXT_VERSION_OK(req_edns.karidns_ext_version) && req_edns.karidns_ext_hash == calc_fnv1a_str(a->elem->name)) {
      ext = true;
      resp_edns.present = true;
      resp_edns.has_karidns_ext = true;
      resp_edns.karidns_ext_version = req_edns.karidns_ext_version;
      resp_edns.karidns_ext_hash = req_edns.karidns_ext_hash;
    }
    if (req_edns.has_expire_query) {
      resp_edns.present = true;
      resp_edns.send_expire = true;
      resp_edns.send_expire_value = ap->expire;      /* a primary zone: the SOA's EXPIRE (RFC 7314 §3) */
    }
  }
  uint8_t *res = malloc(65535);
  if (!res) return false;
  axfr_emit_ctx_t ec;
  axfr_ec_start(&ec, res, a->req, q_offset, a->client_fd, ext, tsig_key, a->tsig_mac, a->tsig_mac_len, &resp_edns, &a->client_addr, a->client_len,
                a->has_server_addr ? &a->server_addr : NULL, a->has_server_addr, a->elem->name);
  uint16_t off = ec.offset;
  bool done = apex_write_soa_rr(res, &off, KARIDNS_AXFR_MSG_LIMIT, a->elem->name, ap, &ec.comp_ctx) == 0;
  if (done) {
    ec.offset = off;
    ec.answers = 1;
    (void)axfr_ec_finish(&ec);       /* (a failed send: the client is gone, the connection is closed below) */
    dbreg_xfr_note(DBREG_XFR_SUMMARY);
  }
  free(res);
  return done;
}

void *axfr_worker_thread(void *arg) {

  atomic_fetch_add_explicit(&g_xfers_running, 1, memory_order_relaxed);
  axfr_worker_args_t *args = (axfr_worker_args_t *)arg;
  zone_db_entry_t *entry = args->entry;

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
  /* D1a step 7: the zone is not in memory.  An IXFR from a client that is up to date is answered from the summary; for anything else the thread waits
   * (not a worker, not holding the read section below) until the zone is read, and counts itself in the entry's active_axfr (db_ingest_xfr_await()).
   * No zone in time: the one error message of RFC 5936 2.2 (SERVFAIL, EDE 14 Not Ready, RFC 8914 4.15; the connection is not just dropped, 4.1.2). */
  bool answered = false;
  uint8_t log_rcode = 0;
  if (!entry && args->elem) {
    if (axfr_send_up_to_date_from_apex(args, pkey)) {
      answered = true;
    } else if (args->await && (entry = args->await(args->elem, args->view_name)) == NULL) {
      axfr_send_error(args->client_fd, args->req, args->req_len, 2, false, 14, "Not Ready", pkey, args->tsig_mac, args->tsig_mac_len, &args->client_addr,
                      args->client_len, &args->server_addr, args->has_server_addr);
      answered = true;
      log_rcode = 2;
    }
  }
  /* 転送の間、arena を読み取り区間で守る。スロットはスレッドごとに確保する
   * (以前は通し番号の剰余で割り当てており、同時に動くスレッドが同じスロットを
   * 共有すると、先に終わった側が区間を閉じてしまった)。*/
  rcu_aux_read_lock();

  /* max-transfer-time-out / max-transfer-idle-out (BIND 9.20; 0 = no limit): send_tcp_dns_message() gives the transfer up after the deadline,
   * and after a send that waited the idle time for the client (the socket is blocking, so SO_SNDTIMEO makes the wait end) */
  g_tcp_send_idle_secs = args->idle_out_secs;
  g_tcp_send_deadline_secs = args->time_out_secs ? time(NULL) + (time_t)args->time_out_secs : 0;
  if (args->idle_out_secs) {
    struct timeval stv = { .tv_sec = (time_t)args->idle_out_secs, .tv_usec = 0 };
    setsockopt(args->client_fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&stv, sizeof stv);
  }
  if (!answered)
    send_axfr_response(args->client_fd, args->qname, args->req, args->req_len,
                       pkey, entry, args->tsig_mac, args->tsig_mac_len,
                       &args->client_addr, args->client_len,
                       args->has_server_addr ? &args->server_addr : NULL, args->has_server_addr);
  g_tcp_send_idle_secs = 0;
  g_tcp_send_deadline_secs = 0;

  submit_response_log(LOG_ACT_SENT, args->client_ip, args->client_port, args->qname,
                      args->qclass, args->qtype, log_rcode, args->has_edns, args->dnssec_ok);

  close(args->client_fd);
  dec_tcp_clients();
  zone_db_snapshot_t *worker_snap = args->snap;
  free(args);
  if (entry)
    atomic_fetch_sub(&entry->active_axfr, 1);
  rcu_aux_read_unlock();
  release_zone_snapshot(worker_snap);
  /* the slot taken when the thread was started (transfers-out); a caller that did not take one (a unit test) must not drive the count negative */
  if (atomic_fetch_sub_explicit(&g_xfr_out_active, 1, memory_order_acq_rel) <= 0) atomic_store_explicit(&g_xfr_out_active, 0, memory_order_release);
  atomic_fetch_sub_explicit(&g_xfers_running, 1, memory_order_relaxed);
  pthread_exit(NULL);
}

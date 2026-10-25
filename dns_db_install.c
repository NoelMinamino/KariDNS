/*
 * dns_db_install.c - one zone from the database loader into a zone entry (see dns_db_install.h).
 */
#include "dns_db_install.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "dns_axfr_ixfr.h"
#include "dns_db_stream.h"
#include "dns_dynamic_update.h"
#include "dns_utils.h"
#include "dns_wire.h"
#include "dns_zone_parser.h"

struct db_zone_build {
  zone_arena_t arena;
  axfr_session_t sess;
  char zone[DNS_NAME_TEXT_SIZE];
  uint64_t rr_count;
  uint32_t flags;               /* ZONE_BEGIN flags (KDB_ZF_*) */
  bool has_serial;
  uint32_t serial;              /* B8t-2: the serial ZONE_BEGIN declared */
};

static void set_why(char *why, size_t whylen, const char *msg) {
  if (why && whylen) snprintf(why, whylen, "%s", msg);
}

db_zone_build_t *db_zone_build_new(const char *zone, uint64_t rr_count, uint32_t flags) {
  db_zone_build_t *b = calloc(1, sizeof(*b));
  if (!b) return NULL;
  zone_arena_init(&b->arena);
  b->flags = flags;
  b->sess.db_stream = true;      /* the strict reading of the Extended AXFR records (dns_server_internal.h) */
  /* a tinydns zone is a tinydns zone also when no RR carries a time stamp or a location (design 3.6a): ZONE_IMAGE_F_TINYDNS */
  if (flags & KDB_ZF_TINYDNS) b->arena.is_tinydns_format = true;
  /* a plain AXFR (design 1.5): no IXFR path, no client serial, no version to thaw */
  b->sess.is_ixfr = false;
  b->sess.client_serial = 0;
  snprintf(b->zone, sizeof(b->zone), "%s", zone);
  b->rr_count = rr_count;
  return b;
}

void db_zone_build_set_serial(db_zone_build_t *b, uint32_t serial) {
  b->has_serial = true;
  b->serial = serial;
}

void db_zone_build_free(db_zone_build_t *b) {
  if (!b) return;
  zone_arena_destroy(&b->arena);
  free(b);
}

int db_zone_build_feed(db_zone_build_t *b, const uint8_t *msg, size_t len, char *why, size_t whylen) {
  if (b->sess.is_finished) {
    set_why(why, whylen, "zone data after the final SOA");
    return -1;
  }
  if (parse_xfr_packet(msg, len, &b->arena, NULL, &b->sess, b->zone) != 0) {
    set_why(why, whylen, "malformed zone data");
    return -1;
  }
  /* the Extended AXFR records (tags, tinydns) are only accepted for a zone that announced them: ZONE_BEGIN flag extended */
  if (!(b->flags & KDB_ZF_EXTENDED) && (b->sess.ext_records > 0 || b->sess.ext_wrapped > 0)) {
    set_why(why, whylen, "Extended AXFR records in a zone that did not announce them");
    return -1;
  }
  if (b->sess.out_of_zone_skipped > 0) {
    set_why(why, whylen, "record with an owner outside the zone");
    return -1;
  }
  if (b->sess.trailing_rrs) {
    set_why(why, whylen, "records after the final SOA");
    return -1;
  }
  return 0;
}

/* the apex SOA with a complete RDATA, or NULL */
static const dns_record_t *find_apex_soa(const zone_arena_t *a, const char *zone) {
  for (size_t k = 0; k < a->count; k++) {
    const dns_record_t *r = &a->records[k];
    if (r->type_code == 6 && r->rdata_count >= 7 && domain_names_match_ci(r->name, zone)) return r;
  }
  return NULL;
}

int db_zone_build_install(db_zone_build_t *b, zone_db_entry_t *entry, bool *notified, char *why, size_t whylen) {
  zone_arena_t *a = &b->arena;
  if (notified) *notified = false;
  if (!b->sess.is_finished) {
    set_why(why, whylen, "zone data ends before the final SOA");
    return -1;
  }
  /* the parser dropped the final SOA and the Extended AXFR marker and definition RRs: the declared count has all of them.
   * B8t-2: a version 3 SOA set (SOA_SET) did not store the opening SOA either, which is the frame, not zone data */
  const bool soa_set = b->sess.soa_set;
  uint64_t got = (uint64_t)a->count + 1 + b->sess.ext_records + (soa_set ? 1 : 0);
  if (got != b->rr_count) {
    snprintf(why, whylen, "RR count mismatch: %llu received, %llu declared", (unsigned long long)got,
             (unsigned long long)b->rr_count);
    return -1;
  }
  if (!domain_names_match_ci(b->sess.initial_soa_name, b->zone) ||
      (!soa_set && (a->count == 0 || a->records[0].type_code != 6 || !domain_names_match_ci(a->records[0].name, b->zone)))) {
    set_why(why, whylen, "the zone does not start with the SOA of its apex");
    return -1;
  }

  size_t nsoa = 0;
  for (size_t k = 0; k < a->count; k++) {
    const dns_record_t *r = &a->records[k];
    if (r->class_val != 1) {
      set_why(why, whylen, "record of a class other than IN");
      return -1;
    }
    if (r->type_code == 6) nsoa++;
  }
  if (!soa_set && nsoa != 1) {
    set_why(why, whylen, "more than one SOA in the zone");
    return -1;
  }
  if (soa_set) {
    /* B8t-2: the apex SOA RRs of the zone are the ones SOA_SET announced (parse_xfr_packet() counted them: all at the apex, all with
     * the serial of the frame); no two of them for the same clients; the frame is the reference SOA; the usual rules for a SOA set */
    if (nsoa != b->sess.soa_set_expected || nsoa != b->sess.soa_set_seen) {
      set_why(why, whylen, "the SOA records of the zone are not the ones SOA_SET announced");
      return -1;
    }
    char serr[320];
    if (zone_arena_check_soa_set(a, b->zone, serr, sizeof(serr)) < 0) {
      snprintf(why, whylen, "%.200s", serr);
      return -1;
    }
    for (size_t i = 0; i < a->count; i++) {
      if (a->records[i].type_code != 6) continue;
      for (size_t j = i + 1; j < a->count; j++)
        if (a->records[j].type_code == 6 && dns_record_same_visibility(&a->records[i], &a->records[j])) {
          set_why(why, whylen, "two SOA records for the same clients");
          return -1;
        }
    }
    const dns_record_t *ref = zone_arena_reference_soa(a, b->zone);
    if (!ref || ref->rdata_count < 7 || parse_ttl_value(ref->rdata[3]) != b->sess.frame_refresh ||
        parse_ttl_value(ref->rdata[4]) != b->sess.frame_retry || parse_ttl_value(ref->rdata[5]) != b->sess.frame_expire) {
      set_why(why, whylen, "the opening SOA is not the reference SOA of the zone");
      return -1;
    }
  }

  /* an RR that cannot be written in wire format is dropped with a warning and the rest is published (as for a zone
   * file and AXFR-in); the SOA is read after that */
  zone_drop_unencodable_logged(a, b->zone, "the database loader");
  const dns_record_t *soa = find_apex_soa(a, b->zone);
  if (!soa) {
    set_why(why, whylen, "the apex SOA cannot be encoded");
    return -1;
  }
  /* a SOA set: the zone-wide values are the frame's (the reference SOA) */
  uint32_t serial = soa_set ? b->sess.initial_soa_serial : (uint32_t)strtoul(soa->rdata[2], NULL, 10);
  uint32_t refresh = soa_set ? b->sess.frame_refresh : parse_ttl_value(soa->rdata[3]);
  uint32_t retry = soa_set ? b->sess.frame_retry : parse_ttl_value(soa->rdata[4]);
  uint32_t expire = soa_set ? b->sess.frame_expire : parse_ttl_value(soa->rdata[5]);


  if (b->has_serial && b->serial != serial) {
    set_why(why, whylen, "the SOA serial is not the one ZONE_BEGIN declared");
    return -1;
  }
  pthread_mutex_lock(&entry->writer_lock);
  if (!wait_for_active_axfr(entry, 5000)) {
    pthread_mutex_unlock(&entry->writer_lock);
    set_why(why, whylen, "busy: a zone transfer is in progress");
    return -1;
  }
  /* like reload_master_zone() for a primary of a file: the values come with the version; R-21: a NOTIFY goes out
   * when the version of a zone that was loaded changes, not at the first load */
  zone_version_t *cur = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
  bool was_loaded = cur->image && cur->image->n_rrs > 0;
  uint32_t old_serial = entry->serial, old_refresh = entry->refresh, old_retry = entry->retry,
           old_expire = entry->expire;
  entry->serial = serial;
  entry->refresh = refresh;
  entry->retry = retry;
  entry->expire = expire;
  if (zone_install_builder(entry, a, "database load") != 0) {
    entry->serial = old_serial;
    entry->refresh = old_refresh;
    entry->retry = old_retry;
    entry->expire = old_expire;
    pthread_mutex_unlock(&entry->writer_lock);
    set_why(why, whylen, "cannot build the zone image");
    return -1;
  }
  pthread_mutex_unlock(&entry->writer_lock);
  if (was_loaded && serial != old_serial) {
    notify_request_send(entry);
    if (notified) *notified = true;
  }
  return 0;
}

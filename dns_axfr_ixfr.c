#define OPENSSL_SUPPRESS_DEPRECATED 1
#include "dns_axfr_ixfr.h"
#include "dns_wire.h"
#include "dns_zone_parser.h"
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

void compute_ixfr_diff(zone_db_entry_t *entry, zone_arena_t *old_arena, zone_arena_t *new_arena) {
  if (!old_arena->hash_table || !new_arena->hash_table) return;
  uint32_t old_serial = 0, new_serial = 0;
  for (size_t i = 0; i < old_arena->count; i++) {
    if (old_arena->records[i].type_code == 6 &&
        domain_names_match_ci(old_arena->records[i].name, entry->domain) &&
        old_arena->records[i].rdata_count >= 3 && old_arena->records[i].rdata[2]) {
      old_serial = strtoul(old_arena->records[i].rdata[2], NULL, 10);
      break;
    }
  }
  for (size_t i = 0; i < new_arena->count; i++) {
    if (new_arena->records[i].type_code == 6 &&
        domain_names_match_ci(new_arena->records[i].name, entry->domain) &&
        new_arena->records[i].rdata_count >= 3 && new_arena->records[i].rdata[2]) {
      new_serial = strtoul(new_arena->records[i].rdata[2], NULL, 10);
      break;
    }
  }
  if (old_serial == 0 || new_serial == 0) return;
  if ((int32_t)(new_serial - old_serial) <= 0) return;

  size_t del_count = 0, add_count = 0;
  for (size_t i = 0; i < old_arena->count; i++) {
    if (!record_exists_in_arena(new_arena, &old_arena->records[i])) del_count++;
  }
  for (size_t i = 0; i < new_arena->count; i++) {
    if (!record_exists_in_arena(old_arena, &new_arena->records[i])) add_count++;
  }
  
  if (del_count + add_count > 10000) return;
  
  ixfr_txn_t *txn = malloc(sizeof(ixfr_txn_t));
  if (!txn) return;
  memset(txn, 0, sizeof(ixfr_txn_t));

  if (del_count > SIZE_MAX / sizeof(dns_record_t) || add_count > SIZE_MAX / sizeof(dns_record_t)) {
      free(txn);
      return;
  }
  if (del_count > 0) {
    txn->deleted = malloc(sizeof(dns_record_t) * del_count);
    if (!txn->deleted) { free(txn); return; }
  }
  if (add_count > 0) {
    txn->added = malloc(sizeof(dns_record_t) * add_count);
    if (!txn->added) { if (txn->deleted) free(txn->deleted); free(txn); return; }
  }

  txn->old_serial = old_serial;
  txn->new_serial = new_serial;
  txn->deleted_count = del_count;
  txn->added_count = add_count;
  atomic_init(&txn->ref_count, 1);
  zone_arena_init(&txn->arena);

  int d_idx = 0;
  for (size_t i = 0; i < old_arena->count; i++) {
    if (!record_exists_in_arena(new_arena, &old_arena->records[i])) {
      txn->deleted[d_idx] = old_arena->records[i];
      txn->deleted[d_idx].name = arena_strdup(&txn->arena, old_arena->records[i].name);
      txn->deleted[d_idx].ttl = arena_strdup(&txn->arena, old_arena->records[i].ttl);
      txn->deleted[d_idx].class_str = arena_strdup(&txn->arena, old_arena->records[i].class_str);
      txn->deleted[d_idx].type = arena_strdup(&txn->arena, old_arena->records[i].type);
      txn->deleted[d_idx].ecs_subnet_tag = old_arena->records[i].ecs_subnet_tag ? arena_strdup(&txn->arena, old_arena->records[i].ecs_subnet_tag) : NULL;
      txn->deleted[d_idx].bind_location_tag = old_arena->records[i].bind_location_tag ? arena_strdup(&txn->arena, old_arena->records[i].bind_location_tag) : NULL;
      for (int j = 0; j < old_arena->records[i].rdata_count; j++) {
         txn->deleted[d_idx].rdata[j] = arena_strdup(&txn->arena, old_arena->records[i].rdata[j]);
      }
      if (old_arena->records[i].generic_len > 0 && old_arena->records[i].generic_data) {
         txn->deleted[d_idx].generic_data = arena_alloc(&txn->arena, old_arena->records[i].generic_len);
         if (txn->deleted[d_idx].generic_data)
           memcpy(txn->deleted[d_idx].generic_data, old_arena->records[i].generic_data, old_arena->records[i].generic_len);
      } else if (old_arena->records[i].generic_data) {
         txn->deleted[d_idx].generic_data = (uint8_t *)"";
      } else {
         txn->deleted[d_idx].generic_data = NULL;
      }
      txn->deleted[d_idx].is_cached = false;
      dns_record_preparse_cache(&txn->arena, &txn->deleted[d_idx]);
      d_idx++;
    }
  }

  int a_idx = 0;
  for (size_t i = 0; i < new_arena->count; i++) {
    if (!record_exists_in_arena(old_arena, &new_arena->records[i])) {
      txn->added[a_idx] = new_arena->records[i];
      txn->added[a_idx].name = arena_strdup(&txn->arena, new_arena->records[i].name);
      txn->added[a_idx].ttl = arena_strdup(&txn->arena, new_arena->records[i].ttl);
      txn->added[a_idx].class_str = arena_strdup(&txn->arena, new_arena->records[i].class_str);
      txn->added[a_idx].type = arena_strdup(&txn->arena, new_arena->records[i].type);
      txn->added[a_idx].ecs_subnet_tag = new_arena->records[i].ecs_subnet_tag ? arena_strdup(&txn->arena, new_arena->records[i].ecs_subnet_tag) : NULL;
      txn->added[a_idx].bind_location_tag = new_arena->records[i].bind_location_tag ? arena_strdup(&txn->arena, new_arena->records[i].bind_location_tag) : NULL;
      for (int j = 0; j < new_arena->records[i].rdata_count; j++) {
         txn->added[a_idx].rdata[j] = arena_strdup(&txn->arena, new_arena->records[i].rdata[j]);
      }
      if (new_arena->records[i].generic_len > 0 && new_arena->records[i].generic_data) {
         txn->added[a_idx].generic_data = arena_alloc(&txn->arena, new_arena->records[i].generic_len);
         if (txn->added[a_idx].generic_data)
           memcpy(txn->added[a_idx].generic_data, new_arena->records[i].generic_data, new_arena->records[i].generic_len);
      } else if (new_arena->records[i].generic_data) {
         txn->added[a_idx].generic_data = (uint8_t *)"";
      } else {
         txn->added[a_idx].generic_data = NULL;
      }
      txn->added[a_idx].is_cached = false;
      dns_record_preparse_cache(&txn->arena, &txn->added[a_idx]);
      a_idx++;
    }
  }

  pthread_mutex_lock(&entry->ixfr_history.lock);
  
  int new_head = entry->ixfr_history.head;
  if (entry->ixfr_history.count == MAX_IXFR_HISTORY) {
    ixfr_txn_t *old_txn = entry->ixfr_history.entries[new_head];
    if (old_txn) {
      if (atomic_fetch_sub_explicit(&old_txn->ref_count, 1, memory_order_acq_rel) == 1) {
        free_ixfr_txn(old_txn);
      }
    }
  } else {
    entry->ixfr_history.count++;
  }

  entry->ixfr_history.entries[new_head] = txn;
  entry->ixfr_history.head = (new_head + 1) % MAX_IXFR_HISTORY;
  pthread_mutex_unlock(&entry->ixfr_history.lock);
}

int parse_xfr_packet(const uint8_t *packet, size_t packet_len,
                     zone_arena_t *standby, zone_arena_t *active,
                     axfr_session_t *session, const char *domain) {
  if (packet_len < DNS_HEADER_SIZE)
    return -1;
  uint16_t qdcount = (packet[4] << 8) | packet[5],
           ancount = (packet[6] << 8) | packet[7];
  size_t offset = DNS_HEADER_SIZE;
  // RFC 5936 §2.2: Even on subsequent messages (session->soa_count > 0),
  // master implementations may include the question section (QDCOUNT > 0).
  // Safely skip any question records present in the packet.
  for (int i = 0; i < qdcount; i++) {
    size_t next_offset;
    if (skip_wire_name(packet, packet_len, offset, &next_offset) != 0)
      return -1;
    if (next_offset + 4 > packet_len)
      return -1;
    offset = next_offset + 4;
  }

  // Check EDNS OPT Option 65153 on the initial packet
  if (session->soa_count == 0) {
    uint16_t nscount = (packet[8] << 8) | packet[9];
    uint16_t arcount = (packet[10] << 8) | packet[11];
    if (arcount > 0) {
      edns_info_t edns = {0};
      if (parse_edns_opt(packet, packet_len, qdcount, ancount, nscount, arcount, &edns) == 0) {
        if (edns.has_karidns_ext && edns.karidns_ext_version == KARIDNS_EXT_VERSION) {
          uint32_t exp_hash = calc_fnv1a_str(domain);
          if (edns.karidns_ext_hash == exp_hash) {
            session->is_extended_mode = true;
          }
        }
      }
    }
  }

  size_t domain_len = strlen(domain);
  for (int i = 0; i < ancount; i++) {
    if (standby->count >= standby->records_cap) {
      size_t new_cap =
          standby->records_cap == 0 ? 16 : standby->records_cap * 2;
      if (new_cap > SIZE_MAX / sizeof(dns_record_t)) return -1;
      dns_record_t *new_records =
          realloc(standby->records, new_cap * sizeof(dns_record_t));
      if (!new_records)
        return -1;
      memset(new_records + standby->records_cap, 0,
             (new_cap - standby->records_cap) * sizeof(dns_record_t));
      standby->records = new_records;
      standby->records_cap = new_cap;
    }
    dns_record_t *rec = &standby->records[standby->count];
    memset(rec, 0, sizeof(*rec));
    uint16_t type;
    if (parse_resource_record(packet, packet_len, &offset, standby, rec,
                              &type) != 0)
      return -1;
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
              rec->ttl_value = orig_ttl;
              rec->type = (char *)get_type_str(orig_type, standby);
              rec->class_str = (orig_class == 1) ? "IN" : "CH";
              char *ttl_buf = arena_alloc(standby, 16);
              if (ttl_buf) {
                snprintf(ttl_buf, 16, "%u", orig_ttl);
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

    if (session->has_current_loc_tag && session->current_loc_tag[0] != '\0') {
      rec->bind_location_tag = arena_strdup(standby, session->current_loc_tag);
    }
    if (session->has_current_ecs_tag && session->current_ecs_tag[0] != '\0') {
      rec->ecs_subnet_tag = arena_strdup(standby, session->current_ecs_tag);
    }
    size_t name_len = strlen(rec->name);
    size_t dlen = domain_len;
    if (dlen > 0 && domain[dlen - 1] == '.') dlen--;
    size_t nlen = name_len;
    if (nlen > 0 && rec->name[nlen - 1] == '.') nlen--;
    if (nlen < dlen)
      return -1;
    if (nlen == dlen) {
      if (strncasecmp(rec->name, domain, dlen) != 0)
        return -1;
    } else {
      if (rec->name[nlen - dlen - 1] != '.' ||
          strncasecmp(rec->name + nlen - dlen, domain, dlen) != 0)
        return -1;
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
        clone_zone_arena(active, standby);
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

int handle_axfr_event(int tcp_fd, zone_db_entry_t *entry,
                      tcp_stream_ctx_t *stream_ctx, axfr_session_t *session,
                      tsig_key_t *tsig_key,
                      const uint8_t *req_mac, size_t req_mac_len) {
  uint8_t *msg;
  uint16_t msg_len;

  zone_arena_t tmp_arena;
  memset(&tmp_arena, 0, sizeof(tmp_arena));
  zone_arena_init(&tmp_arena);

  zone_arena_t *active = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
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
    if (tsig_key) {
      bool has_tsig = packet_has_tsig(msg, msg_len);
      if (!has_tsig) {
        if (!is_subsequent) {
          syslog(LOG_ERR, "[AXFR] First message missing TSIG");
          if (unsigned_msgs) free(unsigned_msgs);
          zone_arena_destroy(&tmp_arena);
          return -1;
        }
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
        memcpy(unsigned_msgs + unsigned_msgs_len, msg, msg_len);
        unsigned_msgs_len += msg_len;
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
        zone_arena_t *cur_active = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
        zone_arena_t *standby = (cur_active == &entry->rcu.arena_a) ? &entry->rcu.arena_b
                                                                    : &entry->rcu.arena_a;
        if (!rcu_writer_wait_until_safe(entry->rcu.retire_epoch, 60000)) {
          pthread_mutex_unlock(&entry->writer_lock);
          if (unsigned_msgs) free(unsigned_msgs);
          zone_arena_destroy(&tmp_arena);
          syslog(LOG_ERR, "[XFR] Inbound transfer swap for zone '%s' aborted: RCU grace period wait timed out", entry->domain);
          return -1;
        }

        if (has_soa) {
          entry->serial = serial;
          entry->refresh = refresh;
          entry->retry = retry;
          entry->expire = expire;
          atomic_store_explicit(&entry->next_check, time(NULL) + entry->refresh, memory_order_release);
          atomic_store_explicit(&entry->last_successful_transfer, time(NULL), memory_order_release);
        }

        clone_zone_arena(&tmp_arena, standby);

        if (build_zone_index(standby, true) != 0) {
          zone_arena_clear_data_pools(standby);
          pthread_mutex_unlock(&entry->writer_lock);
          if (unsigned_msgs) free(unsigned_msgs);
          zone_arena_destroy(&tmp_arena);
          syslog(LOG_ERR, "[Zone] Memory allocation failed while building index after XFR for '%s'", entry->domain);
          return -1;
        }

        zone_db_snapshot_t *cur_snap = acquire_zone_snapshot();
        if (cur_snap) retain_zone_snapshot(cur_snap);
        server_config_t *active_cfg_prelink = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
        zone_config_t *zcfg = find_zone_config_in_view(active_cfg_prelink, entry->view_name, entry->domain);
        additional_from_auth_t policy = (zcfg && zcfg->additional_from_auth_specified)
                                            ? zcfg->additional_from_auth
                                            : (active_cfg_prelink ? active_cfg_prelink->additional_from_auth : ADDITIONAL_AUTH_YES);
        prelink_zone_additional_glue(standby, entry->domain, cur_snap, NULL, policy);
        build_zone_response_cache(standby, active_cfg_prelink, entry->domain);
        if (cur_snap) release_zone_snapshot(cur_snap);

        compute_ixfr_diff(entry, cur_active, standby);
        entry->rcu.retire_epoch = rcu_writer_advance_epoch();
        atomic_store_explicit(&entry->rcu.active, standby,
                              memory_order_release);
        pthread_mutex_unlock(&entry->writer_lock);

        if (session->is_ixfr) {
          atomic_fetch_add_explicit(&entry->observatory.ixfr_success, 1, memory_order_relaxed);
        } else {
          atomic_fetch_add_explicit(&entry->observatory.axfr_success, 1, memory_order_relaxed);
        }
        atomic_store_explicit(&entry->observatory.last_transfer_time, (uint64_t)time(NULL), memory_order_relaxed);

        send_notify_to_all(entry->domain, entry->view_name);
        ret_code = 1;
      } else {
        pthread_mutex_lock(&entry->writer_lock);
        atomic_store_explicit(&entry->next_check, time(NULL) + entry->refresh, memory_order_release);
        atomic_store_explicit(&entry->last_successful_transfer, time(NULL), memory_order_release);
        pthread_mutex_unlock(&entry->writer_lock);
        ret_code = 2;
      }
      break;
    }
  }

  if (unsigned_msgs) free(unsigned_msgs);
  zone_arena_destroy(&tmp_arena);

  // Hook for catalog zone processing
  server_config_t *cfg = acquire_config_snapshot();
  zone_config_t *zcfg = find_zone_config_in_view(cfg, entry->view_name, entry->domain);
  if (zcfg && zcfg->is_catalog) {
      catalog_process_membership(entry, zcfg, entry->view_name);
  }
  release_config_snapshot(cfg);
  return ret_code;
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

  size_t addr_len = (domain_family == AF_INET) ? sizeof(struct sockaddr_in)
                                               : sizeof(struct sockaddr_in6);
  int tcp_fd = broker_connect(domain_family, SOCK_STREAM,
                              (struct sockaddr *)&master_addr, addr_len);
  if (tcp_fd >= 0) {
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
      if (ctx->entry)
        atomic_store_explicit(&ctx->entry->is_transferring, false, memory_order_release);
      free(ctx);
      if (bg_snap)
        release_zone_snapshot(bg_snap);
      atomic_fetch_sub_explicit(&g_xfers_running, 1, memory_order_relaxed);
      pthread_exit(NULL);
    }
    axfr_session_t session = {0};
    uint8_t axfr_req[2048];
    uint16_t req_len = 0;
    uint16_t id = (uint16_t)(arc4random() & 0xFFFF);
    uint8_t *dns_hdr = &axfr_req[2];
    uint32_t active_serial = ctx->entry ? ctx->entry->serial : 0;
    dns_hdr[0] = id >> 8;
    dns_hdr[1] = id & 0xFF;
    dns_hdr[2] = 0x00;
    dns_hdr[3] = 0x00;
    dns_hdr[4] = 0x00;
    dns_hdr[5] = 0x01;
    dns_hdr[6] = 0x00;
    dns_hdr[7] = 0x00;
    dns_hdr[8] = 0x00;
    dns_hdr[9] = active_serial ? 0x01 : 0x00;
    dns_hdr[10] = 0x00;
    dns_hdr[11] = 0x00;
    req_len = 14;
    const char *d = ctx->domain;
    while (*d) {
      const char *dot = strchr_unescaped(d, '.');
      size_t len = dot ? (size_t)(dot - d) : strlen(d);
      if (len > 63)
        len = 63;
      if (req_len + len + 2 > sizeof(axfr_req) - UDP_DEFAULT_MAX_RES_LEN)
        break;
      axfr_req[req_len++] = (uint8_t)len;
      memcpy(&axfr_req[req_len], d, len);
      req_len += len;
      if (!dot)
        break;
      d = dot + 1;
    }
    axfr_req[req_len++] = 0;
    axfr_req[req_len++] = 0x00;
    axfr_req[req_len++] = active_serial ? 251 : 252;
    session.is_ixfr = active_serial ? true : false;
    session.client_serial = active_serial;
    axfr_req[req_len++] = 0x00;
    axfr_req[req_len++] = 1;
    if (active_serial) {
      axfr_req[req_len++] = 0xC0;
      axfr_req[req_len++] = 0x0C;
      axfr_req[req_len++] = 0x00;
      axfr_req[req_len++] = 6;
      axfr_req[req_len++] = 0x00;
      axfr_req[req_len++] = 1;
      axfr_req[req_len++] = 0x00;
      axfr_req[req_len++] = 0;
      axfr_req[req_len++] = 0;
      axfr_req[req_len++] = 0;
      axfr_req[req_len++] = 0x00;
      axfr_req[req_len++] = 22;
      axfr_req[req_len++] = 0;
      axfr_req[req_len++] = 0;
      axfr_req[req_len++] = active_serial >> 24;
      axfr_req[req_len++] = (active_serial >> 16) & 0xFF;
      axfr_req[req_len++] = (active_serial >> 8) & 0xFF;
      axfr_req[req_len++] = active_serial & 0xFF;
      for (int i = 0; i < 16; i++)
        axfr_req[req_len++] = 0;
    }
    axfr_req[req_len++] = 0;
    axfr_req[req_len++] = 0x00;
    axfr_req[req_len++] = 41;
    axfr_req[req_len++] = 0x10;
    axfr_req[req_len++] = 0x00;
    axfr_req[req_len++] = 0x00;
    axfr_req[req_len++] = 0x00;
    axfr_req[req_len++] = 0x00;
    axfr_req[req_len++] = 0x00;
    uint32_t domain_hash = calc_fnv1a_str(ctx->domain);
    axfr_req[req_len++] = 0x00; // RDLEN: 9
    axfr_req[req_len++] = 0x09;
    axfr_req[req_len++] = (EDNS_OPTION_KARIDNS_EXT >> 8) & 0xFF;
    axfr_req[req_len++] = EDNS_OPTION_KARIDNS_EXT & 0xFF;
    axfr_req[req_len++] = 0x00;
    axfr_req[req_len++] = 0x05; // Option Length: 5
    axfr_req[req_len++] = KARIDNS_EXT_VERSION; // 1
    axfr_req[req_len++] = (domain_hash >> 24) & 0xFF;
    axfr_req[req_len++] = (domain_hash >> 16) & 0xFF;
    axfr_req[req_len++] = (domain_hash >> 8) & 0xFF;
    axfr_req[req_len++] = domain_hash & 0xFF;
    dns_hdr[11]++;
    uint8_t req_mac[64];
    size_t req_mac_len = 0;
    if (tsig_key_ptr) {
      size_t p_len = req_len - 2;
      if (tsig_sign_packet(&axfr_req[2], &p_len, sizeof(axfr_req) - 2,
                           tsig_key_ptr, 0, req_mac, &req_mac_len, NULL, 0, false) != 0) {
        syslog(LOG_ERR, "[AXFR] Failed to TSIG-sign request for zone %s", ctx->domain);
        free(stream_ctx);
        close(tcp_fd);
        if (ctx->entry)
          atomic_store_explicit(&ctx->entry->is_transferring, false, memory_order_release);
        free(ctx);
        if (bg_snap)
          release_zone_snapshot(bg_snap);
        atomic_fetch_sub_explicit(&g_xfers_running, 1, memory_order_relaxed);
        pthread_exit(NULL);
      }
      req_len = p_len + 2;
    }
    uint16_t msg_len = req_len - 2;
    axfr_req[0] = msg_len >> 8;
    axfr_req[1] = msg_len & 0xFF;
    if (send(tcp_fd, axfr_req, req_len, 0) == req_len) {
      int axfr_res = handle_axfr_event(tcp_fd, ctx->entry, stream_ctx, &session, tsig_key_ptr,
                                       req_mac_len > 0 ? req_mac : NULL, req_mac_len);
      if (axfr_res == 1) {
        syslog(LOG_NOTICE, "[AXFR] Successfully transferred zone %s from %s", ctx->domain, ctx->master_ip);
      } else if (axfr_res == 2) {
        // Zone is up to date. Do not log to avoid spam on short refresh intervals.
      } else {
        syslog(LOG_ERR, "[AXFR] Failed to transfer zone %s from %s", ctx->domain, ctx->master_ip);
      }
    } else {
      syslog(LOG_ERR, "[AXFR] Failed to send request for zone %s to %s", ctx->domain, ctx->master_ip);
    }
    free(stream_ctx);
    close(tcp_fd);
  } else {
    syslog(LOG_ERR, "[AXFR] Failed to connect to %s for zone %s", ctx->master_ip, ctx->domain);
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

void send_axfr_response(int client_fd, const char *qname __attribute__((unused)), uint8_t *req,
                        uint16_t req_len, tsig_key_t *tsig_key, zone_db_entry_t *entry,
                        uint8_t *req_mac, size_t req_mac_len,
                        const struct sockaddr_storage *client_addr, socklen_t client_len,
                        const struct sockaddr_storage *server_addr, bool has_server_addr) {
  if (!entry) {
    uint8_t res_buf[UDP_DEFAULT_MAX_RES_LEN];
    size_t copy_len = req_len > UDP_DEFAULT_MAX_RES_LEN ? UDP_DEFAULT_MAX_RES_LEN : req_len;
    memcpy(res_buf, req, copy_len);
    res_buf[2] |= 0x84;
    res_buf[3] |= 0x05;
    uint8_t len_prefix[2] = {copy_len >> 8, copy_len & 0xFF};
    write_dnstap_event(NULL, 2 /*AUTH_RESPONSE*/, res_buf, copy_len,
                       client_addr, client_len, server_addr, has_server_addr, IPPROTO_TCP);
    send_tcp_robust(client_fd, len_prefix, 2);
    send_tcp_robust(client_fd, res_buf, copy_len);
    return;
  }
  zone_arena_t *current_zone = NULL;
  do {
    current_zone =
        atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
    atomic_fetch_add_explicit(&current_zone->reader_count, 1,
                              memory_order_acquire);
    if (current_zone ==
        atomic_load_explicit(&entry->rcu.active, memory_order_acquire))
      break;
    atomic_fetch_sub_explicit(&current_zone->reader_count, 1,
                              memory_order_release);
  } while (1);
  if (!current_zone || current_zone->count == 0) {
    atomic_fetch_sub_explicit(&current_zone->reader_count, 1,
                              memory_order_release);
    return;
  }

  uint8_t *res = calloc(1, 65535);
  if (!res) {
    atomic_fetch_sub_explicit(&current_zone->reader_count, 1,
                              memory_order_release);
    return;
  }
  size_t q_offset = DNS_HEADER_SIZE;
  if (skip_wire_name(req, req_len, q_offset, &q_offset) != 0) {
      free(res);
      atomic_fetch_sub_explicit(&current_zone->reader_count, 1, memory_order_release);
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
  if (is_ixfr) {
    uint16_t nscount = (req[8] << 8) | req[9];
    if (nscount > 0) {
      size_t p = q_offset;
      size_t next_p;
      if (skip_wire_name(req, req_len, p, &next_p) == 0) {
        p = next_p;
        if (p + 10 <= req_len) {
          uint16_t auth_type = (req[p] << 8) | req[p+1];
          uint16_t auth_rdlen = (req[p+8] << 8) | req[p+9];
          p += 10;
          if (auth_type == 6 && p + auth_rdlen <= req_len) {
            size_t rp = p;
            if (skip_wire_name(req, req_len, rp, &next_p) == 0) {
              rp = next_p;
              if (skip_wire_name(req, req_len, rp, &next_p) == 0) {
                rp = next_p;
                if (rp + 4 <= p + auth_rdlen) {
                  client_serial = ((uint32_t)req[rp] << 24) | ((uint32_t)req[rp+1] << 16) | ((uint32_t)req[rp+2] << 8) | req[rp+3];
                }
              }
            }
          }
        }
      }
    }
  }
  uint16_t offset = q_offset;
  uint16_t answers = 0;
  uint16_t *res_ancount = (uint16_t *)&res[6];
  memset(res, 0, 65535);
  memcpy(res, req, q_offset); // ここで q_offset までコピーしていることを確認
  res[2] |= 0x84;
  res[3] &= 0xF0;
  res[8] = 0;
  res[9] = 0;
  res[10] = 0;
  res[11] = 0;
  compress_ctx_t comp_ctx;
  memset(&comp_ctx, 0, sizeof(comp_ctx));
  compress_ctx_init_packet(&comp_ctx);
  // 質問セクションの名前（オフセット DNS_HEADER_SIZE）を圧縮テーブルに登録する。
  // これにより最初のレコード（通常はゾーン apex の SOA）の所有者名が
  // 質問セクションへの2バイトポインタとして圧縮され、BIND と同等の
  // メッセージサイズになる（分割後の再初期化コードと同じ処理）。
  register_wire_name_for_compression(res, DNS_HEADER_SIZE, &comp_ctx);
  uint8_t tsig_mac[64]; /* >= EVP_MAX_MD_SIZE */
  static_assert(sizeof(tsig_mac) >= 64, "tsig_mac must be >= EVP_MAX_MD_SIZE (64)");
  size_t tsig_mac_len = req_mac_len;
  if (req_mac_len > 0) memcpy(tsig_mac, req_mac, req_mac_len);
  bool is_subsequent = false;
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
  bool opt_sent = false;
  edns_info_t resp_edns = {0};
  if (is_extended_axfr) {
    resp_edns.present = true;
    resp_edns.has_karidns_ext = true;
    resp_edns.karidns_ext_version = KARIDNS_EXT_VERSION;
    resp_edns.karidns_ext_hash = calc_fnv1a_str(entry->domain);
  }

  int soa_idx = -1;
  for (size_t i = 0; i < current_zone->count; i++) {
    if (current_zone->records[i].type_code == 6 &&
        domain_names_match_ci(current_zone->records[i].name, entry->domain)) {
      soa_idx = i;
      break;
    }
  }
  if (soa_idx < 0) {
    atomic_fetch_sub_explicit(&current_zone->reader_count, 1,
                              memory_order_release);
    free(res);
    return;
  }

  bool send_ixfr = false;
  ixfr_txn_t *txn_list[MAX_IXFR_HISTORY];
  int txn_count = 0;
  uint32_t current_serial = strtoul(current_zone->records[soa_idx].rdata[2], NULL, 10);

  if (is_extended_axfr && is_ixfr) {
    is_ixfr = false;
  }

  if (is_ixfr && client_serial == current_serial) {
    send_ixfr = true;
  } else if (is_ixfr) {
    pthread_mutex_lock(&entry->ixfr_history.lock);
    if (entry->ixfr_history.count > 0) {
    int start_idx = (entry->ixfr_history.head + MAX_IXFR_HISTORY - entry->ixfr_history.count) % MAX_IXFR_HISTORY;
    int found_idx = -1;
    for (int i = 0; i < entry->ixfr_history.count; i++) {
      int idx = (start_idx + i) % MAX_IXFR_HISTORY;
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
        int idx = (start_idx + i) % MAX_IXFR_HISTORY;
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
          int idx = (start_idx + i) % MAX_IXFR_HISTORY;
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

#define SERIALIZE_ADD_RECORD(rec_ptr) do { \
  uint16_t prev_offset = offset; \
  if (serialize_dns_record(res, 65000, &offset, (rec_ptr), &comp_ctx, NULL, 0xFFFFFFFF) < 0) { \
    *res_ancount = htons(answers); \
    if (is_extended_axfr && !opt_sent) { \
      uint16_t arcount = 0; \
      assemble_edns_opt(res, 65535, &prev_offset, &arcount, &resp_edns, 0, true, NULL); \
      res[10] = (arcount >> 8) & 0xFF; \
      res[11] = arcount & 0xFF; \
      opt_sent = true; \
    } \
    if (tsig_key) { \
      size_t sign_len = prev_offset; \
      if (tsig_sign_packet(res, &sign_len, 65535, tsig_key, 0, tsig_mac, &tsig_mac_len, NULL, 0, is_subsequent) != 0) goto axfr_error; \
      is_subsequent = true; \
      prev_offset = sign_len; \
    } \
    uint8_t len_prefix[2] = {prev_offset >> 8, prev_offset & 0xFF}; \
    write_dnstap_event(NULL, 2 /*AUTH_RESPONSE*/, res, prev_offset, \
                       client_addr, client_len, server_addr, has_server_addr, IPPROTO_TCP); \
    if (send_tcp_robust(client_fd, len_prefix, 2) < 0) goto axfr_error; \
    if (send_tcp_robust(client_fd, res, prev_offset) < 0) goto axfr_error; \
    \
    /* 次のパケットの準備（QDCOUNT=1 と質問セクションを必ず引き継ぐ） */ \
    offset = q_offset; \
    answers = 0; \
    memset(res, 0, 65535); \
    memcpy(res, req, q_offset); /* クエリのヘッダと質問セクションをそのままコピー */ \
    res[2] |= 0x84; res[3] &= 0xF0; \
    res[8] = 0; res[9] = 0; res[10] = 0; res[11] = 0; \
    \
    memset(&comp_ctx, 0, sizeof(comp_ctx)); \
    compress_ctx_init_packet(&comp_ctx); \
    /* パケットバッファを破壊せず質問セクションの名前を圧縮テーブルに登録 */ \
    register_wire_name_for_compression(res, DNS_HEADER_SIZE, &comp_ctx); \
    \
    if (serialize_dns_record(res, 65000, &offset, (rec_ptr), &comp_ctx, NULL, 0xFFFFFFFF) < 0) { \
      syslog(LOG_ERR, "[AXFR] Record too large to fit in any TCP message (name=%s type=%u), aborting transfer", \
             (rec_ptr)->name ? (rec_ptr)->name : "(null)", (rec_ptr)->type_code); \
      goto axfr_error; \
    } \
  } \
  answers++; \
} while (0)

#define EMIT_ZONE_RECORD(r_ptr, cur_loc_io, cur_ecs_io) do { \
  dns_record_t *rec_item = (r_ptr); \
  if (!is_extended_axfr) { \
    if (rec_item->bind_location_tag != NULL || \
        rec_item->ecs_subnet_tag != NULL || \
        rec_item->tinydns_loc[0] != 0 || rec_item->tinydns_loc[1] != 0 || \
        rec_item->tinydns_ttd != 0) { \
      /* Skip tagged records in fallback mode */ \
    } else { \
      SERIALIZE_ADD_RECORD(rec_item); \
    } \
  } else { \
    const char *r_loc = rec_item->bind_location_tag ? rec_item->bind_location_tag : ""; \
    if (strcasecmp(r_loc, *(cur_loc_io) ? *(cur_loc_io) : "") != 0) { \
      dns_record_t set_rec; \
      memset(&set_rec, 0, sizeof(set_rec)); \
      set_rec.name = entry->domain; \
      set_rec.type_code = DNS_TYPE_KARIDNS_LOC_STATE; \
      set_rec.class_val = DNS_CLASS_KARIDNS_EXT; \
      set_rec.class_str = "KARIDNS"; \
      set_rec.generic_data = (uint8_t *)r_loc; \
      set_rec.generic_len = strlen(r_loc); \
      SERIALIZE_ADD_RECORD(&set_rec); \
      *(cur_loc_io) = rec_item->bind_location_tag; \
    } \
    const char *r_ecs = rec_item->ecs_subnet_tag ? rec_item->ecs_subnet_tag : ""; \
    if (strcasecmp(r_ecs, *(cur_ecs_io) ? *(cur_ecs_io) : "") != 0) { \
      dns_record_t set_rec; \
      memset(&set_rec, 0, sizeof(set_rec)); \
      set_rec.name = entry->domain; \
      set_rec.type_code = DNS_TYPE_KARIDNS_ECS_STATE; \
      set_rec.class_val = DNS_CLASS_KARIDNS_EXT; \
      set_rec.class_str = "KARIDNS"; \
      set_rec.generic_data = (uint8_t *)r_ecs; \
      set_rec.generic_len = strlen(r_ecs); \
      SERIALIZE_ADD_RECORD(&set_rec); \
      *(cur_ecs_io) = rec_item->ecs_subnet_tag; \
    } \
    if (rec_item->tinydns_loc[0] != 0 || rec_item->tinydns_loc[1] != 0 || rec_item->tinydns_ttd != 0) { \
      dns_record_t wrap_rec; \
      uint8_t wrap_buf[4096]; \
      if (wrap_tinydns_record(rec_item, &wrap_rec, wrap_buf, sizeof(wrap_buf))) { \
        SERIALIZE_ADD_RECORD(&wrap_rec); \
      } else { \
        SERIALIZE_ADD_RECORD(rec_item); \
      } \
    } else { \
      SERIALIZE_ADD_RECORD(rec_item); \
    } \
  } \
} while (0)

  if (send_ixfr) {
    SERIALIZE_ADD_RECORD(&current_zone->records[soa_idx]);
    const char *ixfr_loc = NULL;
    const char *ixfr_ecs = NULL;
    for (int t = 0; t < txn_count; t++) {
      ixfr_txn_t *txn = txn_list[t];
      int soa_del_idx = -1;
      for (int i = 0; i < txn->deleted_count; i++) {
        if (txn->deleted[i].type_code == 6) { soa_del_idx = i; break; }
      }
      if (soa_del_idx >= 0) SERIALIZE_ADD_RECORD(&txn->deleted[soa_del_idx]);
      for (int i = 0; i < txn->deleted_count; i++) {
        if (i == soa_del_idx) continue;
        EMIT_ZONE_RECORD(&txn->deleted[i], &ixfr_loc, &ixfr_ecs);
      }
      int soa_add_idx = -1;
      for (int i = 0; i < txn->added_count; i++) {
        if (txn->added[i].type_code == 6) { soa_add_idx = i; break; }
      }
      if (soa_add_idx >= 0) SERIALIZE_ADD_RECORD(&txn->added[soa_add_idx]);
      for (int i = 0; i < txn->added_count; i++) {
        if (i == soa_add_idx) continue;
        EMIT_ZONE_RECORD(&txn->added[i], &ixfr_loc, &ixfr_ecs);
      }
    }
    if (txn_count > 0) {
      SERIALIZE_ADD_RECORD(&current_zone->records[soa_idx]);
    }
  } else {
    // 1. Initial SOA
    SERIALIZE_ADD_RECORD(&current_zone->records[soa_idx]);

    // Definitions emitted after first SOA in extended mode
    if (is_extended_axfr) {
      for (int i = 0; i < current_zone->bind_location_tag_count; i++) {
        uint8_t tag_buf[2048];
        size_t dlen = pack_tag_def_rdata(tag_buf, sizeof(tag_buf), &current_zone->bind_location_tags[i]);
        if (dlen > 0) {
          dns_record_t tag_rec;
          memset(&tag_rec, 0, sizeof(tag_rec));
          tag_rec.name = entry->domain;
          tag_rec.type_code = DNS_TYPE_KARIDNS_LOC_TAGDEF;
          tag_rec.class_val = DNS_CLASS_KARIDNS_EXT;
          tag_rec.class_str = "KARIDNS";
          tag_rec.generic_data = tag_buf;
          tag_rec.generic_len = dlen;
          SERIALIZE_ADD_RECORD(&tag_rec);
        }
      }
      for (int i = 0; i < current_zone->bind_ecs_tag_count; i++) {
        uint8_t tag_buf[2048];
        size_t dlen = pack_tag_def_rdata(tag_buf, sizeof(tag_buf), &current_zone->bind_ecs_tags[i]);
        if (dlen > 0) {
          dns_record_t tag_rec;
          memset(&tag_rec, 0, sizeof(tag_rec));
          tag_rec.name = entry->domain;
          tag_rec.type_code = DNS_TYPE_KARIDNS_ECS_TAGDEF;
          tag_rec.class_val = DNS_CLASS_KARIDNS_EXT;
          tag_rec.class_str = "KARIDNS";
          tag_rec.generic_data = tag_buf;
          tag_rec.generic_len = dlen;
          SERIALIZE_ADD_RECORD(&tag_rec);
        }
      }
      server_config_t *axfr_cfg = acquire_config_snapshot();
      zone_config_t *axfr_zcfg = axfr_cfg ? find_zone_config_in_view(axfr_cfg, entry->view_name, entry->domain) : NULL;
      char **trusted_res = (current_zone->bind_ecs_trusted_resolver_count > 0 && current_zone->bind_ecs_trusted_resolvers)
                            ? current_zone->bind_ecs_trusted_resolvers : NULL;
      int trusted_count = trusted_res ? current_zone->bind_ecs_trusted_resolver_count : 0;
      if (!trusted_res) {
        trusted_res = (axfr_zcfg && axfr_zcfg->ecs_trusted_resolvers) ? axfr_zcfg->ecs_trusted_resolvers
                                                                       : (axfr_cfg ? axfr_cfg->ecs_trusted_resolvers : NULL);
        trusted_count = (axfr_zcfg && axfr_zcfg->ecs_trusted_resolvers) ? axfr_zcfg->ecs_trusted_resolvers_count
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
        SERIALIZE_ADD_RECORD(&trusted_rec);
      }
      if (axfr_cfg) release_config_snapshot(axfr_cfg);
      for (int i = 0; i < current_zone->location_count; i++) {
        const tinydns_location_entry_t *loc = &current_zone->locations[i];
        uint8_t loc_buf[8];
        loc_buf[0] = loc->code[0];
        loc_buf[1] = loc->code[1];
        loc_buf[2] = loc->prefix_len;
        if (loc->prefix_len > 0) {
          memcpy(&loc_buf[3], loc->prefix, loc->prefix_len);
        }
        dns_record_t loc_rec;
        memset(&loc_rec, 0, sizeof(loc_rec));
        loc_rec.name = entry->domain;
        loc_rec.type_code = DNS_TYPE_KARIDNS_TINYDNS_LOCDEF;
        loc_rec.class_val = DNS_CLASS_KARIDNS_EXT;
        loc_rec.class_str = "KARIDNS";
        loc_rec.generic_data = loc_buf;
        loc_rec.generic_len = 3 + loc->prefix_len;
        SERIALIZE_ADD_RECORD(&loc_rec);
      }
    }

    const char *current_stream_loc = NULL;
    const char *current_stream_ecs = NULL;
    for (size_t i = 0; i < current_zone->count; i++) {
      if ((int)i == soa_idx)
        continue;
      EMIT_ZONE_RECORD(&current_zone->records[i], &current_stream_loc, &current_stream_ecs);
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
        SERIALIZE_ADD_RECORD(&set_rec);
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
        SERIALIZE_ADD_RECORD(&set_rec);
      }
    }

    // 3. Trailing SOA
    SERIALIZE_ADD_RECORD(&current_zone->records[soa_idx]);
  }
  if (answers > 0) {
    *res_ancount = htons(answers);
    if (is_extended_axfr && !opt_sent) {
      uint16_t arcount = 0;
      assemble_edns_opt(res, 65535, &offset, &arcount, &resp_edns, 0, true, NULL);
      res[10] = (arcount >> 8) & 0xFF;
      res[11] = arcount & 0xFF;
      opt_sent = true;
    }
    if (tsig_key) {
      size_t sign_len = offset;
      if (tsig_sign_packet(res, &sign_len, 65535, tsig_key, 0, tsig_mac,
                           &tsig_mac_len, NULL, 0, is_subsequent) != 0) {
        goto axfr_error;
      }
      offset = sign_len;
    }
    uint8_t len_prefix[2] = {offset >> 8, offset & 0xFF};
    write_dnstap_event(NULL, 2 /*AUTH_RESPONSE*/, res, offset,
                       client_addr, client_len, server_addr, has_server_addr, IPPROTO_TCP);
    if (send_tcp_robust(client_fd, len_prefix, 2) < 0)
      goto axfr_error;
    if (send_tcp_robust(client_fd, res, offset) < 0)
      goto axfr_error;
  }

  for (int t = 0; t < txn_count; t++) {
    if (atomic_fetch_sub_explicit(&txn_list[t]->ref_count, 1, memory_order_acq_rel) == 1) {
       free_ixfr_txn(txn_list[t]);
    }
  }
  if (res) free(res);
  atomic_fetch_sub_explicit(&current_zone->reader_count, 1, memory_order_release);
  return;

axfr_error:
  for (int t = 0; t < txn_count; t++) {
    if (atomic_fetch_sub_explicit(&txn_list[t]->ref_count, 1, memory_order_acq_rel) == 1) {
       free_ixfr_txn(txn_list[t]);
    }
  }
  if (res) free(res);
  atomic_fetch_sub_explicit(&current_zone->reader_count, 1, memory_order_release);
}

void *axfr_worker_thread(void *arg) {
  atomic_fetch_add_explicit(&g_xfers_running, 1, memory_order_relaxed);
  axfr_worker_args_t *args = (axfr_worker_args_t *)arg;
  zone_db_entry_t *entry = args->entry;
  static _Atomic int axfr_slot_counter = ATOMIC_VAR_INIT(0);
  int slot = (int)(atomic_fetch_add(&axfr_slot_counter, 1) % MAX_AXFR_RCU_WORKERS);
  rcu_reader_enter(&g_axfr_rcu_ctxs[slot]);

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
  rcu_reader_exit(&g_axfr_rcu_ctxs[slot]);
  release_zone_snapshot(worker_snap);
  atomic_fetch_sub_explicit(&g_xfers_running, 1, memory_order_relaxed);
  pthread_exit(NULL);
}

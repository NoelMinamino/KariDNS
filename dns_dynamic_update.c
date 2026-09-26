#define OPENSSL_SUPPRESS_DEPRECATED 1
#include "dns_dynamic_update.h"
#include "dns_server_internal.h"
#include "dns_wire.h"
#include "dns_utils.h"
#include "dns_axfr_ixfr.h"
#include "dns_snapshot_rcu.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

uint32_t bump_soa_serial_in_arena(zone_arena_t *arena, const char *zone_name) {
  if (!arena || !zone_name) return 0;
  uint32_t new_serial = 0;
  for (size_t i = 0; i < arena->count; i++) {
    if (arena->records[i].type_code == 6 && domain_names_match_ci(arena->records[i].name, zone_name) && arena->records[i].rdata_count >= 3) {
      if (arena->records[i].rdata[2]) {
        uint32_t serial = strtoul(arena->records[i].rdata[2], NULL, 10);
        serial++;
        if (serial == 0) serial = 1;
        new_serial = serial;
        char buf[32];
        snprintf(buf, sizeof(buf), "%u", serial);
        /* [C-2] arena_strdup 失敗時は NULL が代入されることを防ぐ */
        char *new_rdata = arena_strdup(arena, buf);
        if (!new_rdata) {
          syslog(LOG_ERR, "[Update] arena_strdup failed bumping SOA serial; aborting update");
          return 0;
        }
        arena->records[i].rdata[2] = new_rdata;
        arena->records[i].is_cached = false;
        dns_record_preparse_cache(arena, &arena->records[i]);
      }
      break;
    }
  }
  return new_serial;
}

int handle_dynamic_update(const uint8_t *req, size_t req_len,
                          zone_db_entry_t *entry,
                          const char *client_ip,
                          const char *matched_key_name) {
  pthread_mutex_lock(&entry->writer_lock);
  if (!wait_for_active_axfr(entry, 5000)) {
    pthread_mutex_unlock(&entry->writer_lock);
    syslog(LOG_WARNING, "[Update] Dynamic update on zone '%s' rejected: active AXFR in progress.", entry->domain);
    return 2; // SERVFAIL
  }

  zone_arena_t *z_active = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
  zone_arena_t *z_standby = (z_active == &entry->rcu.arena_a) ? &entry->rcu.arena_b : &entry->rcu.arena_a;
  if (!rcu_writer_wait_until_safe(entry->rcu.retire_epoch, 60000)) {
    pthread_mutex_unlock(&entry->writer_lock);
    syslog(LOG_ERR, "[Update] Dynamic update on zone '%s' aborted: RCU grace period wait timed out", entry->domain);
    return 2; // SERVFAIL
  }

  clone_zone_arena(z_active, z_standby);

  int prcount = 0, upcount = 0;
  int rcode = process_update_sections(req, req_len, entry->domain, z_standby, &prcount, &upcount);
  if (rcode != 0) {
    zone_arena_clear_data_pools(z_standby);
    pthread_mutex_unlock(&entry->writer_lock);
    return rcode;
  }

  uint32_t new_serial = bump_soa_serial_in_arena(z_standby, entry->domain);
  if (new_serial != 0) {
    atomic_store_explicit(&entry->serial, new_serial, memory_order_release);
  }

  if (build_zone_index(z_standby, true) != 0) {
    zone_arena_clear_data_pools(z_standby);
    pthread_mutex_unlock(&entry->writer_lock);
    syslog(LOG_ERR, "[Zone] Memory allocation failed while building index after Update for '%s'", entry->domain);
    return 2; // SERVFAIL
  }

  zone_db_snapshot_t *cur_snap = acquire_zone_snapshot();
  if (cur_snap) retain_zone_snapshot(cur_snap);
  server_config_t *active_cfg_prelink = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
  zone_config_t *zcfg = find_zone_config_in_view(active_cfg_prelink, entry->view_name, entry->domain);
  additional_from_auth_t policy = (zcfg && zcfg->additional_from_auth_specified)
                                      ? zcfg->additional_from_auth
                                      : (active_cfg_prelink ? active_cfg_prelink->additional_from_auth : ADDITIONAL_AUTH_YES);
  prelink_zone_additional_glue(z_standby, entry->domain, cur_snap, NULL, policy);
  build_zone_response_cache(z_standby, active_cfg_prelink, entry->domain);
  if (cur_snap) release_zone_snapshot(cur_snap);

  compute_ixfr_diff(entry, z_active, z_standby);

  entry->rcu.retire_epoch = rcu_writer_advance_epoch();
  atomic_store_explicit(&entry->rcu.active, z_standby, memory_order_release);
  pthread_mutex_unlock(&entry->writer_lock);

  atomic_store_explicit(&entry->notify_now, true, memory_order_release);
  if (g_control_kq != -1) {
    struct kevent ev;
    EV_SET(&ev, 2, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
    kevent(g_control_kq, &ev, 1, NULL, 0, NULL);
  }

  syslog(LOG_NOTICE,
         "[Update] client=%s key=%s zone='%s' prcount=%d upcount=%d "
         "(in-memory only, will revert on reload)",
         client_ip, matched_key_name, entry->domain, prcount, upcount);

  return 0; // NOERROR
}

static void send_single_notify(const uint8_t *req, size_t req_len,
                               const struct sockaddr *dest_addr, socklen_t addr_len,
                               const char *notify_source) {
  udp_ipc_t msg;
  memset(&msg, 0, sizeof(msg));
  msg.sock_fd_idx = -1; // -1 = NOTIFY / Dynamic UDP
  size_t copy_len = addr_len <= sizeof(msg.client_addr) ? addr_len : sizeof(msg.client_addr);
  memcpy(&msg.client_addr, dest_addr, copy_len);
  msg.addr_len = (uint16_t)addr_len;
  msg.payload_len = (uint16_t)req_len;

  int family = dest_addr->sa_family;
  if (notify_source && *notify_source) {
    if (family == AF_INET &&
        inet_pton(AF_INET, notify_source,
                  &msg.source_addr.sin.sin_addr) == 1) {
      msg.source_addr.ss_family = AF_INET;
      msg.has_source_addr = true;
    } else if (family == AF_INET6 &&
               inet_pton(AF_INET6, notify_source,
                         &msg.source_addr.sin6.sin6_addr) == 1) {
      msg.source_addr.ss_family = AF_INET6;
      msg.has_source_addr = true;
    }
  }

  uint8_t buf[2048];
  /* Defense in depth: all current callers build a small, internally-generated
   * NOTIFY packet (well under this limit), but nothing here enforced that.
   * Without this check, any future caller (or refactor) passing a larger
   * req_len would silently overflow this stack buffer. */
  if (sizeof(msg) + req_len > sizeof(buf)) {
    syslog(LOG_ERR, "[Notify] NOTIFY payload too large (%zu bytes), dropping", req_len);
    return;
  }
  memcpy(buf, &msg, sizeof(msg));
  memcpy(buf + sizeof(msg), req, req_len);
  /* [H-1] send 戻り値を検査してエラーをログに記録する */
  if (send(g_notify_ipc[1], buf, sizeof(msg) + req_len, 0) < 0) {
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
      syslog(LOG_WARNING, "[Notify] send to notify IPC failed: %m");
    }
  }
}

static bool is_addr_notified(const struct sockaddr_storage *addrs, int count, const struct sockaddr *target) {
  for (int i = 0; i < count; i++) {
    if (addrs[i].ss_family != target->sa_family) continue;
    if (target->sa_family == AF_INET) {
      struct sockaddr_in *a = (struct sockaddr_in *)&addrs[i];
      struct sockaddr_in *b = (struct sockaddr_in *)target;
      if (a->sin_port == b->sin_port && a->sin_addr.s_addr == b->sin_addr.s_addr) return true;
    } else if (target->sa_family == AF_INET6) {
      struct sockaddr_in6 *a = (struct sockaddr_in6 *)&addrs[i];
      struct sockaddr_in6 *b = (struct sockaddr_in6 *)target;
      if (a->sin6_port == b->sin6_port && memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(struct in6_addr)) == 0) return true;
    }
  }
  return false;
}

void send_notify_to_all(const char *domain, const char *view_name) {
  server_config_t *active = acquire_config_snapshot();
  zone_db_snapshot_t *snap = acquire_zone_snapshot();
  if (snap) retain_zone_snapshot(snap);
  if (!active && !snap) {
    if (active) release_config_snapshot(active);
    if (snap) release_zone_snapshot(snap);
    return;
  }

  zone_config_t *zone = active ? find_zone_config_in_view(active, view_name, domain) : NULL;
  const char *notify_source = zone ? zone->notify_source : NULL;

  uint8_t req[UDP_DEFAULT_MAX_RES_LEN];
  memset(req, 0, DNS_HEADER_SIZE);
  uint16_t id = (uint16_t)(arc4random() & 0xFFFF);
  req[0] = id >> 8;
  req[1] = id & 0xFF;
  req[2] = 0x24; // Opcode = NOTIFY (0x20) | AA = 1 (0x04) (RFC 1996 §3.4)
  req[3] = 0;
  req[4] = 0;
  req[5] = 1;
  size_t offset = DNS_HEADER_SIZE;
  long w = write_uncompressed_name(req, offset, sizeof(req), domain);
  if (w > 0) offset += (size_t)w;
  req[offset++] = 0;
  req[offset++] = 6;
  req[offset++] = 0;
  req[offset++] = 1;

  struct sockaddr_storage notified_addrs[64];
  int notified_count = 0;

  // 1. Send to also-notify servers
  if (zone) {
    for (int i = 0; i < zone->also_notify_count && notified_count < 64; i++) {
      struct sockaddr_storage dest_addr;
      memset(&dest_addr, 0, sizeof(dest_addr));
      if (inet_pton(AF_INET, zone->also_notify[i].ip,
                    &((struct sockaddr_in *)&dest_addr)->sin_addr) == 1) {
        dest_addr.ss_family = AF_INET;
        ((struct sockaddr_in *)&dest_addr)->sin_port = htons(zone->also_notify[i].port);
      } else if (inet_pton(AF_INET6, zone->also_notify[i].ip,
                           &((struct sockaddr_in6 *)&dest_addr)->sin6_addr) == 1) {
        dest_addr.ss_family = AF_INET6;
        ((struct sockaddr_in6 *)&dest_addr)->sin6_port = htons(zone->also_notify[i].port);
      } else {
        continue;
      }
      if (!is_addr_notified(notified_addrs, notified_count, (struct sockaddr *)&dest_addr)) {
        socklen_t slen = (dest_addr.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
        send_single_notify(req, offset, (struct sockaddr *)&dest_addr, slen, notify_source);
        notified_addrs[notified_count++] = dest_addr;
      }
    }
  }

  // 2. Send to NS records (RFC 1996 §3.2)
  if (snap) {
    view_snapshot_t *view = NULL;
    if (view_name) {
      for (size_t v = 0; v < snap->view_count; v++) {
        if (strcasecmp(snap->views[v].name, view_name) == 0) {
          view = &snap->views[v];
          break;
        }
      }
    }
    if (!view && snap->view_count > 0) {
      view = &snap->views[0];
    }
    if (view) {
      zone_db_entry_t *entry = find_zone_in_view(view, domain);
      if (entry) {
        zone_arena_t *arena = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
        if (arena && arena->hash_size > 0 && arena->hash_table) {
          // Find SOA MNAME to exclude master itself
          const char *mname = NULL;
          uint32_t apex_hash = calc_fnv1a_str(entry->domain);
          size_t apex_idx = apex_hash & (arena->hash_size - 1);
          for (int i = arena->hash_table[apex_idx]; i != -1; i = arena->records[i].next_record) {
            if (arena->records[i].type_code == 6 && domain_names_match_ci(arena->records[i].name, entry->domain)) {
              if (arena->records[i].rdata_count >= 1 && arena->records[i].rdata[0]) {
                mname = arena->records[i].rdata[0];
              }
              break;
            }
          }

          // Scan apex NS records
          for (int i = arena->hash_table[apex_idx]; i != -1; i = arena->records[i].next_record) {
            dns_record_t *rec = &arena->records[i];
            if (rec->type_code == 2 && domain_names_match_ci(rec->name, entry->domain)) {
              if (rec->rdata_count < 1 || !rec->rdata[0]) continue;
              const char *ns_target = rec->rdata[0];
              if (mname && domain_names_match_ci(ns_target, mname)) continue;

              // Resolve in-zone glue or sibling zone glue
              // A. In arena
              uint32_t t_hash = calc_fnv1a_str(ns_target);
              size_t t_idx = t_hash & (arena->hash_size - 1);
              bool found_target = false;
              for (int j = arena->hash_table[t_idx]; j != -1; j = arena->records[j].next_record) {
                dns_record_t *g_rec = &arena->records[j];
                if ((g_rec->type_code == 1 || g_rec->type_code == 28) && domain_names_match_ci(g_rec->name, ns_target)) {
                  struct sockaddr_storage dest_addr;
                  memset(&dest_addr, 0, sizeof(dest_addr));
                  if (g_rec->type_code == 1 && g_rec->rdata_count >= 1) {
                    if (inet_pton(AF_INET, g_rec->rdata[0], &((struct sockaddr_in *)&dest_addr)->sin_addr) == 1) {
                      dest_addr.ss_family = AF_INET;
                      ((struct sockaddr_in *)&dest_addr)->sin_port = htons(53);
                      if (!is_addr_notified(notified_addrs, notified_count, (struct sockaddr *)&dest_addr)) {
                        send_single_notify(req, offset, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_in), notify_source);
                        if (notified_count < 64) notified_addrs[notified_count++] = dest_addr;
                      }
                      found_target = true;
                    }
                  } else if (g_rec->type_code == 28 && g_rec->rdata_count >= 1) {
                    if (inet_pton(AF_INET6, g_rec->rdata[0], &((struct sockaddr_in6 *)&dest_addr)->sin6_addr) == 1) {
                      dest_addr.ss_family = AF_INET6;
                      ((struct sockaddr_in6 *)&dest_addr)->sin6_port = htons(53);
                      if (!is_addr_notified(notified_addrs, notified_count, (struct sockaddr *)&dest_addr)) {
                        send_single_notify(req, offset, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_in6), notify_source);
                        if (notified_count < 64) notified_addrs[notified_count++] = dest_addr;
                      }
                      found_target = true;
                    }
                  }
                }
              }

              // B. If not found in arena, check sibling zone in view
              if (!found_target && view) {
                zone_db_entry_t *sib_entry = find_zone_in_view(view, ns_target);
                if (sib_entry && sib_entry != entry) {
                  zone_arena_t *sib_arena = atomic_load_explicit(&sib_entry->rcu.active, memory_order_acquire);
                  if (sib_arena && sib_arena->hash_size > 0 && sib_arena->hash_table) {
                    size_t s_idx = t_hash & (sib_arena->hash_size - 1);
                    for (int j = sib_arena->hash_table[s_idx]; j != -1; j = sib_arena->records[j].next_record) {
                      dns_record_t *g_rec = &sib_arena->records[j];
                      if ((g_rec->type_code == 1 || g_rec->type_code == 28) && domain_names_match_ci(g_rec->name, ns_target)) {
                        struct sockaddr_storage dest_addr;
                        memset(&dest_addr, 0, sizeof(dest_addr));
                        if (g_rec->type_code == 1 && g_rec->rdata_count >= 1) {
                          if (inet_pton(AF_INET, g_rec->rdata[0], &((struct sockaddr_in *)&dest_addr)->sin_addr) == 1) {
                            dest_addr.ss_family = AF_INET;
                            ((struct sockaddr_in *)&dest_addr)->sin_port = htons(53);
                            if (!is_addr_notified(notified_addrs, notified_count, (struct sockaddr *)&dest_addr)) {
                              send_single_notify(req, offset, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_in), notify_source);
                              if (notified_count < 64) notified_addrs[notified_count++] = dest_addr;
                            }
                          }
                        } else if (g_rec->type_code == 28 && g_rec->rdata_count >= 1) {
                          if (inet_pton(AF_INET6, g_rec->rdata[0], &((struct sockaddr_in6 *)&dest_addr)->sin6_addr) == 1) {
                            dest_addr.ss_family = AF_INET6;
                            ((struct sockaddr_in6 *)&dest_addr)->sin6_port = htons(53);
                            if (!is_addr_notified(notified_addrs, notified_count, (struct sockaddr *)&dest_addr)) {
                              send_single_notify(req, offset, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_in6), notify_source);
                              if (notified_count < 64) notified_addrs[notified_count++] = dest_addr;
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
        }
      }
    }
  }

  if (snap && notified_count > 0) {
    view_snapshot_t *v_snap = NULL;
    if (view_name) {
      for (size_t v = 0; v < snap->view_count; v++) {
        if (strcasecmp(snap->views[v].name, view_name) == 0) {
          v_snap = &snap->views[v];
          break;
        }
      }
    }
    if (!v_snap && snap->view_count > 0) v_snap = &snap->views[0];
    if (v_snap) {
      zone_db_entry_t *entry = find_zone_in_view(v_snap, domain);
      if (entry) {
        atomic_fetch_add_explicit(&entry->observatory.notify_sent, notified_count, memory_order_relaxed);
        atomic_store_explicit(&entry->observatory.last_notify_time, (uint64_t)time(NULL), memory_order_relaxed);
      }
    }
  }

  if (snap) release_zone_snapshot(snap);
  if (active) release_config_snapshot(active);
}

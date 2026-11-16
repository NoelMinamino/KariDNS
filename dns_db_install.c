/*
 * dns_db_install.c - one zone image from the database loader into a zone entry (see dns_db_install.h).
 */
#include "dns_db_install.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dns_log.h"
#include <time.h>

#include "dns_axfr_ixfr.h"
#include "dns_dynamic_update.h"
#include "dns_utils.h"
#include "dns_wire.h"

static void set_why(char *why, size_t whylen, const char *msg) {
  if (why && whylen) snprintf(why, whylen, "%s", msg);
}

static uint32_t cap_ttl(uint32_t v) { return v > 0x7FFFFFFFu ? 0x7FFFFFFFu : v; }

int db_zone_install_image(zone_db_entry_t *entry, zone_image_t *img, bool *notified, char *why, size_t whylen) {
  if (notified) *notified = false;
  /* the zone-wide values are those of the reference SOA (the image checked the rest: zone_image_validate_ex()) */
  zone_image_soa_t n;
  const uint32_t soa = zone_image_apex_soa(img);
  if (soa == ZONE_IMAGE_NONE || zone_image_soa(img, soa, NULL, 0, NULL, 0, &n) != 0) {
    set_why(why, whylen, "the apex SOA cannot be read");
    return -1;
  }
  /* max-records, max-records-per-type, max-types-per-name, max-zone-ttl of the zone, as for a zone file and a transfer (batch 7) */
  if (zone_limits_gate_image(entry, img, "database load") != 0) {
    set_why(why, whylen, "the zone is over a limit of the configuration (see the log)");
    return -1;
  }
  zone_version_t *ver = zone_version_new_ext(img, dns_alloc_size(img, img->total_size), NULL, NULL);      /* (the version frees the image with free()) */
  if (!ver) {
    set_why(why, whylen, "out of memory");
    return -1;
  }
  pthread_mutex_lock(&entry->writer_lock);     /* (R11: a transfer of the zone that runs meanwhile goes on with the version it pinned) */
  /* like reload_master_zone() for a primary of a file: the values come with the version; R-21: a NOTIFY goes out when the version of a zone that was loaded changes, not at the first load */
  zone_version_t *cur = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
  const bool was_loaded = cur->image && cur->image->n_rrs > 0;
  const uint32_t old_serial = entry->serial;
  entry->serial = n.serial;
  entry->refresh = cap_ttl(n.refresh);
  entry->retry = cap_ttl(n.retry);
  entry->expire = cap_ttl(n.expire);
  /* karictl rollback: the version a primary's install replaces is kept for the zone's rollback-window */
  zone_install_version(entry, ver, cur, !entry->is_secondary && !entry->is_catalog_member);
  atomic_store_explicit(&entry->updated, false, memory_order_release);                    /* what an UPDATE changed is replaced by the database's version */
  pthread_mutex_unlock(&entry->writer_lock);
  if (was_loaded && n.serial != old_serial) {
    notify_request_send(entry);
    if (notified) *notified = true;
  }
  return 0;
}

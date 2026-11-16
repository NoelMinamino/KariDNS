#ifndef DNS_DB_INSTALL_H
#define DNS_DB_INSTALL_H

/*
 * dns_db_install.h - publish the zone image of a database zone into a zone entry (beta design 1.5, 4.1; 0.7 M3).
 *
 * The loader builds the image (dns_pdns_reader.c, zone_image_freeze()); the Backend reassembles and validates it
 * (zone_image_validate_ex(), dns_db_ingest.c) and hands it over here.  The limits of the zone (max-records, max-records-per-type,
 * max-types-per-name, max-zone-ttl: server, view and zone options) are checked on the image, the entry takes the serial and the
 * SOA timers of the zone's reference SOA, the image becomes the entry's next version (zone_install_version(): glue, response
 * cache, the IXFR difference against the version in memory, publication) under the entry's writer_lock.
 *
 * Everything here is for the load path (it allocates); a rejected zone leaves the entry as it was.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dns_server_internal.h"
#include "dns_zone_image.h"

/* img: a malloc()ed, validated image (zone_image_validate_ex() accepted it for this zone); it is the entry's version from here on and is
 * freed with it, so the caller gives it up when this returns 0 and keeps it when this returns -1.  0: published (*notified: a NOTIFY was
 * requested because the serial of a zone that was loaded before changed); -1: not published (a limit; why says which), entry unchanged. */
int db_zone_install_image(zone_db_entry_t *entry, zone_image_t *img, bool *notified, char *why, size_t whylen);

#endif /* DNS_DB_INSTALL_H */

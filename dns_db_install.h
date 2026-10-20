#ifndef DNS_DB_INSTALL_H
#define DNS_DB_INSTALL_H

/*
 * dns_db_install.h - build one zone from the ZONE_DATA messages of the database loader and publish it into a zone
 * entry (beta design 1.5, 4.1; milestone B4b).
 *
 * The messages are (Extended) AXFR response messages: parse_xfr_packet() reads them with a per-zone axfr_session_t set
 * up as a plain AXFR (is_ixfr = false, client_serial = 0, no active version: no IXFR path, and a serial that goes down
 * is accepted).  At ZONE_END the checks of design 1.5 run (declared count, SOA framing, apex SOA owner = zone name,
 * every owner inside the zone: parse_xfr_packet() only skips out-of-zone RRs of an AXFR, the loader must never send
 * them, so here they reject the zone), the RRs that cannot be written are dropped, and zone_install_builder() (shared
 * with AXFR-in) publishes the image under the entry's writer_lock.
 *
 * Everything here is for the load path (it allocates); a rejected zone leaves the entry as it was.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dns_server_internal.h"

typedef struct db_zone_build db_zone_build_t;

/* zone: canonical absolute name; rr_count: the count ZONE_BEGIN declared (both SOAs counted).  NULL: out of memory */
db_zone_build_t *db_zone_build_new(const char *zone, uint64_t rr_count);
/* One ZONE_DATA message.  0, or -1 with a short reason in why (no bytes of the message in it) */
int db_zone_build_feed(db_zone_build_t *b, const uint8_t *msg, size_t len, char *why, size_t whylen);
/* ZONE_END: check and publish into entry.  0: published (*notified: a NOTIFY was requested because the serial of a
 * zone that was loaded before changed); -1: rejected or not published, entry unchanged, reason in why */
int db_zone_build_install(db_zone_build_t *b, zone_db_entry_t *entry, bool *notified, char *why, size_t whylen);
void db_zone_build_free(db_zone_build_t *b);

#endif /* DNS_DB_INSTALL_H */

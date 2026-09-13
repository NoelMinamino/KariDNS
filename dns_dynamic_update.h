#ifndef DNS_DYNAMIC_UPDATE_H
#define DNS_DYNAMIC_UPDATE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "dns_server_internal.h"

uint32_t bump_soa_serial_in_arena(zone_arena_t *arena);
int handle_dynamic_update(const uint8_t *req, size_t req_len,
                          zone_db_entry_t *entry,
                          const char *client_ip,
                          const char *matched_key_name);
void send_notify_to_all(const char *domain, const char *view_name);

#endif /* DNS_DYNAMIC_UPDATE_H */

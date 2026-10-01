#ifndef DNS_DYNAMIC_UPDATE_H
#define DNS_DYNAMIC_UPDATE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>
#include <time.h>
#include "dns_server_internal.h"

uint32_t bump_soa_serial_in_arena(zone_arena_t *arena, const char *zone_name);
int handle_dynamic_update(const uint8_t *req, size_t req_len,
                          zone_db_entry_t *entry,
                          const char *client_ip,
                          const char *matched_key_name);
/* 送信する NOTIFY (RFC 1996)。send_notify_to_all() / notify_retransmit_due() / notify_handle_response() は
 * 応答待ちの表を持つ制御スレッドだけが呼ぶ。他のスレッドは notify_request_send() で制御スレッドに頼む。 */
void send_notify_to_all(const char *domain, const char *view_name);
void notify_request_send(zone_db_entry_t *entry);
void notify_retransmit_due(time_t now);
void notify_handle_response(const uint8_t *msg, size_t len, const struct sockaddr *from);

#endif /* DNS_DYNAMIC_UPDATE_H */

#ifndef DNS_DYNAMIC_UPDATE_H
#define DNS_DYNAMIC_UPDATE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>
#include <time.h>
#include "dns_server_internal.h"

uint32_t bump_soa_serial_in_arena(zone_arena_t *arena, const char *zone_name);
/* The serial an UPDATE gives a zone (serial-update-method, BIND dns_update_soaserial()); method is SUM_* (dns_config_parser.h), now the clock */
uint32_t update_next_serial(uint32_t serial, int method, time_t now);
uint32_t bump_soa_serial_method(zone_arena_t *arena, const char *zone_name, int method, time_t now);
int handle_dynamic_update(const uint8_t *req, size_t req_len,
                          zone_db_entry_t *entry,
                          const char *client_ip,
                          const char *matched_key_name);
/* 送信する NOTIFY (RFC 1996)。send_notify_to_all() / notify_retransmit_due() / notify_handle_response() は
 * 応答待ちの表を持つ制御スレッドだけが呼ぶ。他のスレッドは notify_request_send() で制御スレッドに頼む。 */
void send_notify_to_all(zone_db_entry_t *entry);
void notify_request_send(zone_db_entry_t *entry);
/* D1a step 7: the NOTIFY messages of a zone whose data is out of memory (el: its directory element; view_name: the view of the directory).  Control thread only. */
void notify_send_nonresident(const zdir_elem_t *el, const char *view_name);
void notify_retransmit_due(time_t now);
void notify_handle_response(const uint8_t *msg, size_t len, const struct sockaddr *from);

/* NOTIFY over TCP (`tcp-only yes` in a `server` statement, and the retry after the UDP attempts; BIND 9.20 notify_send_toaddr() /
 * notify_done()): the exchange runs in a thread of its own over a connection of the connect broker.  notify_tcp_roundtrip() is the exchange on
 * a connected socket (RFC 1035 §4.2.2: a two-octet length before each message): it sends msg and reads the one message that answers it into
 * resp (at least a DNS header, at most cap octets) within timeout_ms.  notify_tcp_in_flight() is the number of threads running. */
enum { NOTIFY_TCP_OK = 0, NOTIFY_TCP_TIMEOUT, NOTIFY_TCP_IO, NOTIFY_TCP_CLOSED, NOTIFY_TCP_BAD_LENGTH };
int notify_tcp_roundtrip(int fd, const uint8_t *msg, size_t len, uint8_t *resp, size_t cap, size_t *resp_len, int timeout_ms);
int notify_tcp_in_flight(void);

#endif /* DNS_DYNAMIC_UPDATE_H */

#ifndef DNSTAP_DECODE_H
#define DNSTAP_DECODE_H

/*
 * dnstap (https://dnstap.info/) protobuf decoder shared by dag (--replay) and karidns-tapstat.
 *
 * The input is the payload of a Frame Streams data frame: a dnstap.Dnstap message whose field 14 is the
 * dnstap.Message.  Every byte is untrusted: each length is checked against the room left, a field that does
 * not fit ends the walk, and nothing is copied except by parse_dnstap_data_frame_*() into its own buffers.
 * Unknown fields are skipped; groups (wire types 3 and 4) end the walk.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define DNSTAP_REPLAY_WIRE_MAX 4096

/* One dnstap.Message with pointers into the frame it was decoded from (valid while that buffer is). */
typedef struct {
    uint32_t message_type;      /* field 1: 1 = AUTH_QUERY, 2 = AUTH_RESPONSE, ... */
    uint32_t socket_family;     /* field 2: 1 = INET, 2 = INET6 (0 when absent) */
    uint32_t socket_protocol;   /* field 3: 1 = UDP, 2 = TCP, ... */
    bool has_query_addr;        /* field 4 present and at most 16 bytes */
    const uint8_t *query_addr;
    size_t query_addr_len;
    uint16_t query_port;        /* field 6 */
    bool has_response_addr;     /* field 5 present and at most 16 bytes */
    const uint8_t *response_addr;
    size_t response_addr_len;
    uint16_t response_port;     /* field 7 */
    const uint8_t *query_zone;  /* field 11: the zone name in wire format */
    size_t query_zone_len;
    const uint8_t *query_msg;   /* field 10 */
    size_t query_msg_len;
    const uint8_t *response_msg; /* field 14 */
    size_t response_msg_len;
} dnstap_msg_t;

/* Decodes the dnstap.Dnstap in data[0..len) and the dnstap.Message in it.  False when there is no non-empty message
 * (field 14), in which case *out is zeroed.  A message cut short or with a bad field still returns what came before. */
bool dnstap_decode_message(const uint8_t *data, size_t len, dnstap_msg_t *out);

typedef struct {
    uint8_t message_type;      // 1 = AUTH_QUERY, 2 = AUTH_RESPONSE
    uint8_t protocol;          // IPPROTO_UDP(17) / IPPROTO_TCP(6)
    uint8_t client_addr[16];
    uint16_t client_port;
    bool has_wire;
    uint8_t wire[DNSTAP_REPLAY_WIRE_MAX];
    size_t wire_len;
} dnstap_frame_info_t;

bool parse_dnstap_data_frame(const uint8_t *data, size_t len, uint8_t *out_dns, size_t *out_dns_len);
bool parse_dnstap_data_frame_ex(const uint8_t *data, size_t len, uint8_t *out_dns, size_t *out_dns_len, char *out_transport, size_t out_transport_len);
bool parse_dnstap_data_frame_full(const uint8_t *data, size_t len, dnstap_frame_info_t *out);

#endif /* DNSTAP_DECODE_H */

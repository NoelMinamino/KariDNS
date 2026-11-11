#include <string.h>

#include "dnstap_decode.h"

/* protobuf varint (at most 10 bytes); 0 when it does not end inside buf */
static size_t pb_decode_varint(const uint8_t *buf, size_t len, uint64_t *val) {
    if (!buf || len == 0 || !val) return 0;
    uint64_t result = 0;
    unsigned int shift = 0;
    size_t i = 0;
    while (i < len && i < 10) {
        uint8_t byte = buf[i];
        if (shift < 64) {
            result |= ((uint64_t)(byte & 0x7F)) << shift;
        }
        i++;
        if (!(byte & 0x80)) {
            *val = result;
            return i;
        }
        shift += 7;
    }
    return 0;
}

/* One field of a message starting at buf[off].  Returns the bytes used (0 = stop walking).
 * For wire type 2, *bytes / *blen point into buf. */
static size_t pb_next_field(const uint8_t *buf, size_t len, size_t off, uint32_t *field_num, uint64_t *varint,
                            const uint8_t **bytes, size_t *blen, int *wire_type) {
    uint64_t key = 0;
    size_t c = pb_decode_varint(buf + off, len - off, &key);
    if (c == 0) return 0;
    size_t pos = off + c;
    *field_num = (uint32_t)(key >> 3);
    *wire_type = (int)(key & 0x07);
    *bytes = NULL;
    *blen = 0;
    *varint = 0;
    if (*wire_type == 0) {
        c = pb_decode_varint(buf + pos, len - pos, varint);
        if (c == 0) return 0;
        pos += c;
    } else if (*wire_type == 2) {
        uint64_t flen = 0;
        c = pb_decode_varint(buf + pos, len - pos, &flen);
        if (c == 0) return 0;
        pos += c;
        if (flen > len - pos) return 0;
        *bytes = buf + pos;
        *blen = (size_t)flen;
        pos += (size_t)flen;
    } else if (*wire_type == 5) {
        if (len - pos < 4) return 0;
        pos += 4;
    } else if (*wire_type == 1) {
        if (len - pos < 8) return 0;
        pos += 8;
    } else {
        return 0;
    }
    return pos - off;
}

bool dnstap_decode_message(const uint8_t *data, size_t len, dnstap_msg_t *out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!data || len == 0) return false;

    const uint8_t *msg = NULL;
    size_t msg_len = 0;
    size_t off = 0;
    while (off < len) {
        uint32_t fn; uint64_t v; const uint8_t *b; size_t bl; int wt;
        size_t used = pb_next_field(data, len, off, &fn, &v, &b, &bl, &wt);
        if (used == 0) break;
        off += used;
        if (wt == 2 && fn == 14) { // dnstap.Dnstap.message
            msg = b;
            msg_len = bl;
            break;
        }
    }
    if (!msg || msg_len == 0) return false;

    off = 0;
    while (off < msg_len) {
        uint32_t fn; uint64_t v; const uint8_t *b; size_t bl; int wt;
        size_t used = pb_next_field(msg, msg_len, off, &fn, &v, &b, &bl, &wt);
        if (used == 0) break;
        off += used;
        if (wt == 0) {
            switch (fn) {
            case 1: out->message_type = (uint32_t)v; break;
            case 2: out->socket_family = (uint32_t)v; break;
            case 3: out->socket_protocol = (uint32_t)v; break;
            case 6: out->query_port = (uint16_t)v; break;
            case 7: out->response_port = (uint16_t)v; break;
            default: break;
            }
        } else if (wt == 2) {
            switch (fn) {
            case 4:
                if (bl <= 16) { out->has_query_addr = true; out->query_addr = b; out->query_addr_len = bl; }
                break;
            case 5:
                if (bl <= 16) { out->has_response_addr = true; out->response_addr = b; out->response_addr_len = bl; }
                break;
            case 10: out->query_msg = b; out->query_msg_len = bl; break;
            case 11: out->query_zone = b; out->query_zone_len = bl; break;
            case 14: out->response_msg = b; out->response_msg_len = bl; break;
            default: break;
            }
        }
    }
    return true;
}

bool parse_dnstap_data_frame_ex(const uint8_t *data, size_t len, uint8_t *out_dns, size_t *out_dns_len,
                                char *out_transport, size_t out_transport_len) {
    if (!data || len == 0 || !out_dns || !out_dns_len) return false;
    if (out_transport && out_transport_len > 0) out_transport[0] = '\0';
    dnstap_msg_t m;
    if (!dnstap_decode_message(data, len, &m)) return false;

    if (!m.query_msg || m.query_msg_len < 12 || m.query_msg_len > DNSTAP_REPLAY_WIRE_MAX) return false;

    // Must be a query (QR == 0) and have at least 1 question
    if ((m.query_msg[2] & 0x80) != 0) return false;
    uint16_t qdcount = ((uint16_t)m.query_msg[4] << 8) | m.query_msg[5];
    if (qdcount == 0) return false;

    memcpy(out_dns, m.query_msg, m.query_msg_len);
    *out_dns_len = m.query_msg_len;

    if (out_transport && out_transport_len > 0) {
        if (m.socket_protocol == 2) {
            strncpy(out_transport, "tcp", out_transport_len - 1);
            out_transport[out_transport_len - 1] = '\0';
        } else if (m.socket_protocol == 1) {
            strncpy(out_transport, "udp", out_transport_len - 1);
            out_transport[out_transport_len - 1] = '\0';
        } else {
            out_transport[0] = '\0';
        }
    }
    return true;
}

bool parse_dnstap_data_frame(const uint8_t *data, size_t len, uint8_t *out_dns, size_t *out_dns_len) {
    return parse_dnstap_data_frame_ex(data, len, out_dns, out_dns_len, NULL, 0);
}

bool parse_dnstap_data_frame_full(const uint8_t *data, size_t len, dnstap_frame_info_t *out) {
    if (!data || len == 0 || !out) return false;
    memset(out, 0, sizeof(*out));
    dnstap_msg_t m;
    if (!dnstap_decode_message(data, len, &m)) return false;

    out->message_type = (uint8_t)m.message_type;
    out->protocol = (m.socket_protocol == 2) ? 6 : 17; // 2=TCP, 1=UDP

    if (m.has_query_addr) {
        memcpy(out->client_addr, m.query_addr, m.query_addr_len);
        out->client_port = m.query_port;
    } else if (m.has_response_addr) {
        memcpy(out->client_addr, m.response_addr, m.response_addr_len);
        out->client_port = m.response_port;
    }

    const uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (m.message_type == 1 /* AUTH_QUERY */) {
        wire = m.query_msg ? m.query_msg : m.response_msg;
        wire_len = m.query_msg ? m.query_msg_len : m.response_msg_len;
    } else { // AUTH_RESPONSE or others
        wire = m.response_msg ? m.response_msg : m.query_msg;
        wire_len = m.response_msg ? m.response_msg_len : m.query_msg_len;
    }

    if (!wire || wire_len < 12 || wire_len > DNSTAP_REPLAY_WIRE_MAX) return false;

    memcpy(out->wire, wire, wire_len);
    out->wire_len = wire_len;
    out->has_wire = true;
    return true;
}

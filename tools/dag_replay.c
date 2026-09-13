#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <io.h>
#define close(s) closesocket(s)
#ifndef MSG_WAITALL
#define MSG_WAITALL 0
#endif

/* Winsock API casting wrappers for uint8_t* buffers to avoid signedness warnings */
#define send(s, b, l, f) send((s), (const char *)(b), (int)(l), (f))
#define recv(s, b, l, f) recv((s), (char *)(b), (int)(l), (f))
#define sendto(s, b, l, f, to, tolen) sendto((s), (const char *)(b), (int)(l), (f), (to), (int)(tolen))
#define recvfrom(s, b, l, f, from, fromlen) recvfrom((s), (char *)(b), (int)(l), (f), (from), (int *)(fromlen))
#ifndef strcasecmp
#define strcasecmp _stricmp
#endif
#ifndef strncasecmp
#define strncasecmp _strnicmp
#endif
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <strings.h>
#endif

#include "dag_replay.h"
#include "dag_pcap_l4.h"
#include "dag_tcp_reassembly.h"


#define REPLAY_QUEUE_CAPACITY 1024
#define MAX_REPLAY_PACKET_LEN 4096

typedef struct {
    uint8_t pkt[MAX_REPLAY_PACKET_LEN];
    size_t pkt_len;
    uint64_t seq;
    char transport[16];
    bool has_recorded_resp;
    uint8_t recorded_resp[MAX_REPLAY_PACKET_LEN];
    size_t recorded_resp_len;
} replay_task_t;

typedef struct {
    replay_task_t tasks[REPLAY_QUEUE_CAPACITY];
    size_t head;
    size_t tail;
    size_t count;
    bool done;
    pthread_mutex_t lock;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} replay_queue_t;

typedef struct {
    uint64_t queries_sent;
    uint64_t responses_received;
    uint64_t timeouts;
    uint64_t rcode_counts[16];
    double total_rtt_ms;
} server_stats_t;

typedef struct {
    uint64_t total_compared;
    uint64_t identical;
    uint64_t rcode_mismatches;
    uint64_t flags_mismatches;
    uint64_t ancount_mismatches;
    uint64_t rrset_mismatches;
    uint64_t glue_missing_diffs;
    uint64_t edns_diffs;
    uint64_t dnssec_rrsig_diffs;
    uint64_t dnssec_nsec_diffs;
    uint64_t cname_chain_diffs;
} diff_stats_t;

typedef struct {
    char input_path[512];
    char server1_host[128];
    int server1_port;
    char server1_transport[16];
    char server2_host[128];
    int server2_port;
    char server2_transport[16];
    bool has_server2;
    int rate_qps;
    int num_workers;
    bool do_diff;
    bool compare_recorded;
    bool output_json;
    char transport[16];
    bool transport_explicit;
    int max_queries;
    bool ignore_ttl;
    int timeout_ms;
    int stop_after;
    bool dnssec;
    char output_diff_path[512];
    FILE *diff_fp;
} replay_options_t;

typedef struct {
    replay_queue_t *queue;
    const replay_options_t *opts;
    server_stats_t s1_stats;
    server_stats_t s2_stats;
    diff_stats_t diff_stats;
    pthread_mutex_t stats_lock;
} worker_shared_t;

static inline size_t pb_decode_varint(const uint8_t *buf, size_t len, uint64_t *val) {
    if (!buf || len == 0 || !val) return 0;
    uint64_t result = 0;
    size_t shift = 0;
    size_t i = 0;
    while (i < len && i < 10) {
        uint8_t byte = buf[i];
        result |= ((uint64_t)(byte & 0x7F)) << shift;
        i++;
        if (!(byte & 0x80)) {
            *val = result;
            return i;
        }
        shift += 7;
    }
    return 0;
}

static inline uint32_t pcap_read_u32(const uint8_t *p, bool is_le) {
    if (is_le) {
        return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    } else {
        return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | ((uint32_t)p[3]);
    }
}

bool parse_pcap_packet_ex(const uint8_t *data, size_t len, uint32_t linktype,
                          uint8_t *out_dns, size_t *out_dns_len,
                          char *out_transport, size_t out_transport_len) {
    if (!data || len < 14 || !out_dns || !out_dns_len) return false;
    if (out_transport && out_transport_len > 0) out_transport[0] = '\0';

    pcap_l4_info_t l4;
    if (!pcap_extract_l4(data, len, linktype, &l4)) return false;
    if (l4.l4_proto != 17 && l4.l4_proto != 6) return false;

    const uint8_t *dns_data = NULL;
    size_t dns_len = 0;

    if (l4.l4_proto == 17) {
        if (l4.l4_payload_len < 12) return false;
        dns_data = l4.l4_payload;
        dns_len = l4.l4_payload_len;
        if (out_transport && out_transport_len > 0) {
            strncpy(out_transport, "udp", out_transport_len - 1);
            out_transport[out_transport_len - 1] = '\0';
        }
    } else {
        if (l4.l4_payload_len < 2) return false;
        uint16_t tcp_dns_len = ((uint16_t)l4.l4_payload[0] << 8) | l4.l4_payload[1];
        if (2 + (size_t)tcp_dns_len > l4.l4_payload_len) {
            dns_len = l4.l4_payload_len - 2;
        } else {
            dns_len = tcp_dns_len;
        }
        dns_data = l4.l4_payload + 2;
        if (out_transport && out_transport_len > 0) {
            strncpy(out_transport, "tcp", out_transport_len - 1);
            out_transport[out_transport_len - 1] = '\0';
        }
    }

    if (dns_len < 12 || dns_len > MAX_REPLAY_PACKET_LEN) return false;
    if ((dns_data[2] & 0x80) != 0) return false; // QR=0 only
    uint16_t qdcount = ((uint16_t)dns_data[4] << 8) | dns_data[5];
    if (qdcount == 0) return false;

    memcpy(out_dns, dns_data, dns_len);
    *out_dns_len = dns_len;
    return true;
}

bool parse_pcap_packet(const uint8_t *data, size_t len, uint32_t linktype, uint8_t *out_dns, size_t *out_dns_len) {
    return parse_pcap_packet_ex(data, len, linktype, out_dns, out_dns_len, NULL, 0);
}

bool parse_dnstap_data_frame_ex(const uint8_t *data, size_t len, uint8_t *out_dns, size_t *out_dns_len,
                                char *out_transport, size_t out_transport_len) {
    if (!data || len == 0 || !out_dns || !out_dns_len) return false;
    if (out_transport && out_transport_len > 0) out_transport[0] = '\0';
    size_t off = 0;
    const uint8_t *msg_data = NULL;
    size_t msg_len = 0;

    while (off < len) {
        uint64_t key = 0;
        size_t consumed = pb_decode_varint(data + off, len - off, &key);
        if (consumed == 0) break;
        off += consumed;
        uint32_t field_num = (uint32_t)(key >> 3);
        uint32_t wire_type = (uint32_t)(key & 0x07);

        if (wire_type == 0) {
            uint64_t v = 0;
            size_t c = pb_decode_varint(data + off, len - off, &v);
            if (c == 0) break;
            off += c;
        } else if (wire_type == 2) {
            uint64_t field_len = 0;
            size_t c = pb_decode_varint(data + off, len - off, &field_len);
            if (c == 0) break;
            off += c;
            if (off + field_len > len) break;
            if (field_num == 14) { // dnstap.Dnstap.message
                msg_data = data + off;
                msg_len = (size_t)field_len;
                break;
            }
            off += field_len;
        } else if (wire_type == 5) {
            if (off + 4 > len) break;
            off += 4;
        } else if (wire_type == 1) {
            if (off + 8 > len) break;
            off += 8;
        } else {
            break;
        }
    }

    if (!msg_data || msg_len == 0) return false;

    off = 0;
    const uint8_t *query_msg = NULL;
    size_t query_len = 0;
    uint32_t socket_protocol = 0;

    while (off < msg_len) {
        uint64_t key = 0;
        size_t consumed = pb_decode_varint(msg_data + off, msg_len - off, &key);
        if (consumed == 0) break;
        off += consumed;
        uint32_t field_num = (uint32_t)(key >> 3);
        uint32_t wire_type = (uint32_t)(key & 0x07);

        if (wire_type == 0) {
            uint64_t v = 0;
            size_t c = pb_decode_varint(msg_data + off, msg_len - off, &v);
            if (c == 0) break;
            off += c;
            if (field_num == 3) { // socket_protocol (1 = UDP, 2 = TCP)
                socket_protocol = (uint32_t)v;
            }
        } else if (wire_type == 2) {
            uint64_t field_len = 0;
            size_t c = pb_decode_varint(msg_data + off, msg_len - off, &field_len);
            if (c == 0) break;
            off += c;
            if (off + field_len > msg_len) break;
            if (field_num == 10) { // query_message
                query_msg = msg_data + off;
                query_len = (size_t)field_len;
            }
            off += field_len;
        } else if (wire_type == 5) {
            if (off + 4 > msg_len) break;
            off += 4;
        } else if (wire_type == 1) {
            if (off + 8 > msg_len) break;
            off += 8;
        } else {
            break;
        }
    }

    if (!query_msg || query_len < 12 || query_len > MAX_REPLAY_PACKET_LEN) return false;

    // Must be a query (QR == 0) and have at least 1 question
    if ((query_msg[2] & 0x80) != 0) return false;
    uint16_t qdcount = ((uint16_t)query_msg[4] << 8) | query_msg[5];
    if (qdcount == 0) return false;

    memcpy(out_dns, query_msg, query_len);
    *out_dns_len = query_len;

    if (out_transport && out_transport_len > 0) {
        if (socket_protocol == 2) {
            strncpy(out_transport, "tcp", out_transport_len - 1);
            out_transport[out_transport_len - 1] = '\0';
        } else if (socket_protocol == 1) {
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

    size_t off = 0;
    const uint8_t *msg_data = NULL;
    size_t msg_len = 0;

    while (off < len) {
        uint64_t key = 0;
        size_t consumed = pb_decode_varint(data + off, len - off, &key);
        if (consumed == 0) break;
        off += consumed;
        uint32_t field_num = (uint32_t)(key >> 3);
        uint32_t wire_type = (uint32_t)(key & 0x07);

        if (wire_type == 0) {
            uint64_t v = 0;
            size_t c = pb_decode_varint(data + off, len - off, &v);
            if (c == 0) break;
            off += c;
        } else if (wire_type == 2) {
            uint64_t field_len = 0;
            size_t c = pb_decode_varint(data + off, len - off, &field_len);
            if (c == 0) break;
            off += c;
            if (off + field_len > len) break;
            if (field_num == 14) { // dnstap.Dnstap.message
                msg_data = data + off;
                msg_len = (size_t)field_len;
                break;
            }
            off += field_len;
        } else if (wire_type == 5) {
            if (off + 4 > len) break;
            off += 4;
        } else if (wire_type == 1) {
            if (off + 8 > len) break;
            off += 8;
        } else {
            break;
        }
    }

    if (!msg_data || msg_len == 0) return false;

    off = 0;
    const uint8_t *query_msg = NULL;
    size_t query_len = 0;
    const uint8_t *resp_msg = NULL;
    size_t resp_len = 0;
    uint32_t message_type = 0;
    uint32_t socket_protocol = 0;
    uint8_t q_addr[16] = {0};
    bool has_q_addr = false;
    uint16_t q_port = 0;
    uint8_t r_addr[16] = {0};
    bool has_r_addr = false;
    uint16_t r_port = 0;

    while (off < msg_len) {
        uint64_t key = 0;
        size_t consumed = pb_decode_varint(msg_data + off, msg_len - off, &key);
        if (consumed == 0) break;
        off += consumed;
        uint32_t field_num = (uint32_t)(key >> 3);
        uint32_t wire_type = (uint32_t)(key & 0x07);

        if (wire_type == 0) {
            uint64_t v = 0;
            size_t c = pb_decode_varint(msg_data + off, msg_len - off, &v);
            if (c == 0) break;
            off += c;
            if (field_num == 1) {
                message_type = (uint32_t)v;
            } else if (field_num == 3) {
                socket_protocol = (uint32_t)v;
            } else if (field_num == 6) {
                q_port = (uint16_t)v;
            } else if (field_num == 7) {
                r_port = (uint16_t)v;
            }
        } else if (wire_type == 2) {
            uint64_t field_len = 0;
            size_t c = pb_decode_varint(msg_data + off, msg_len - off, &field_len);
            if (c == 0) break;
            off += c;
            if (off + field_len > msg_len) break;
            if (field_num == 4) { // query_address
                if (field_len <= 16) {
                    memcpy(q_addr, msg_data + off, (size_t)field_len);
                    has_q_addr = true;
                }
            } else if (field_num == 5) { // response_address
                if (field_len <= 16) {
                    memcpy(r_addr, msg_data + off, (size_t)field_len);
                    has_r_addr = true;
                }
            } else if (field_num == 10) { // query_message
                query_msg = msg_data + off;
                query_len = (size_t)field_len;
            } else if (field_num == 14) { // response_message
                resp_msg = msg_data + off;
                resp_len = (size_t)field_len;
            }
            off += field_len;
        } else if (wire_type == 5) {
            if (off + 4 > msg_len) break;
            off += 4;
        } else if (wire_type == 1) {
            if (off + 8 > msg_len) break;
            off += 8;
        } else {
            break;
        }
    }

    out->message_type = (uint8_t)message_type;
    out->protocol = (socket_protocol == 2) ? 6 : 17; // 2=TCP, 1=UDP

    if (has_q_addr) {
        memcpy(out->client_addr, q_addr, 16);
        out->client_port = q_port;
    } else if (has_r_addr) {
        memcpy(out->client_addr, r_addr, 16);
        out->client_port = r_port;
    }

    const uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (message_type == 1 /* AUTH_QUERY */) {
        wire = query_msg ? query_msg : resp_msg;
        wire_len = query_msg ? query_len : resp_len;
    } else { // AUTH_RESPONSE or others
        wire = resp_msg ? resp_msg : query_msg;
        wire_len = resp_msg ? resp_len : query_len;
    }

    if (!wire || wire_len < 12 || wire_len > MAX_REPLAY_PACKET_LEN) return false;

    memcpy(out->wire, wire, wire_len);
    out->wire_len = wire_len;
    out->has_wire = true;
    return true;
}

#define MAX_SECTION_RRS 128
#define MAX_NAME_BUF 256
#define MAX_RDATA_BUF 512

typedef struct {
    uint16_t class_code;
    uint16_t type;
    uint32_t ttl;
    char name[MAX_NAME_BUF];
    uint16_t rdlength;
    uint8_t rdata[MAX_RDATA_BUF];
} replay_rr_t;

typedef struct {
    bool present;
    uint16_t udp_payload_size;
    uint8_t ext_rcode;
    uint8_t version;
    bool do_bit;
    bool has_cookie;
    bool has_ecs;
    uint16_t ecs_family;
    uint8_t ecs_source_prefix;
    uint8_t ecs_scope_prefix;
    uint8_t ecs_addr[16];
    size_t ecs_addr_len;
    uint8_t other_opts[512];
    size_t other_opts_len;
} replay_edns_t;

typedef struct {
    replay_rr_t ans1[MAX_SECTION_RRS];
    replay_rr_t ans2[MAX_SECTION_RRS];
    replay_rr_t auth1[MAX_SECTION_RRS];
    replay_rr_t auth2[MAX_SECTION_RRS];
    replay_rr_t add1[MAX_SECTION_RRS];
    replay_rr_t add2[MAX_SECTION_RRS];
    replay_edns_t edns1;
    replay_edns_t edns2;
} diff_scratch_t;

static size_t expand_wire_name_buf(const uint8_t *pkt, size_t pkt_len, size_t offset,
                                   size_t *next_offset, char *out_name, size_t out_cap) {
    if (!pkt || offset >= pkt_len) return 0;
    size_t cur = offset;
    size_t name_pos = 0;
    bool jumped = false;
    int jumps = 0;

    if (out_name && out_cap > 0) out_name[0] = '\0';

    while (cur < pkt_len && jumps <= 32) {
        uint8_t len = pkt[cur];
        if (len == 0) {
            if (!jumped && next_offset) {
                *next_offset = cur + 1;
            }
            if (out_name && out_cap > 0) {
                if (name_pos == 0) {
                    if (out_cap > 1) {
                        out_name[0] = '.';
                        out_name[1] = '\0';
                    }
                } else {
                    out_name[name_pos] = '\0';
                }
            }
            return 1;
        }

        if ((len & 0xC0) == 0xC0) {
            if (cur + 1 >= pkt_len) return 0;
            uint16_t ptr = (((uint16_t)(len & 0x3F)) << 8) | pkt[cur + 1];
            if (ptr >= pkt_len) return 0;
            if (!jumped) {
                if (next_offset) *next_offset = cur + 2;
                jumped = true;
            }
            cur = ptr;
            jumps++;
            continue;
        }

        if (len > 63 || cur + 1 + len > pkt_len) return 0;
        cur++;
        for (uint8_t i = 0; i < len; i++) {
            char ch = (char)tolower((unsigned char)pkt[cur + i]);
            if (out_name && name_pos + 2 < out_cap) {
                out_name[name_pos++] = ch;
            }
        }
        if (out_name && name_pos + 1 < out_cap) {
            out_name[name_pos++] = '.';
        }
        cur += len;
    }
    return 0;
}

static size_t parse_section_rrs(const uint8_t *pkt, size_t pkt_len, size_t offset,
                                uint16_t count, bool is_additional,
                                replay_rr_t *rrs, size_t *out_rr_count,
                                replay_edns_t *edns) {
    if (!pkt || offset > pkt_len) return 0;
    size_t cur = offset;
    size_t num_parsed = 0;

    for (uint16_t i = 0; i < count; i++) {
        if (cur >= pkt_len) return 0;
        size_t next_off = 0;
        char name[MAX_NAME_BUF];
        if (!expand_wire_name_buf(pkt, pkt_len, cur, &next_off, name, sizeof(name))) {
            return 0;
        }
        cur = next_off;
        if (cur + 10 > pkt_len) return 0;

        uint16_t type = ((uint16_t)pkt[cur] << 8) | pkt[cur + 1];
        uint16_t class_code = ((uint16_t)pkt[cur + 2] << 8) | pkt[cur + 3];
        uint32_t ttl = ((uint32_t)pkt[cur + 4] << 24) | ((uint32_t)pkt[cur + 5] << 16) |
                       ((uint32_t)pkt[cur + 6] << 8) | pkt[cur + 7];
        uint16_t rdlen = ((uint16_t)pkt[cur + 8] << 8) | pkt[cur + 9];
        cur += 10;
        if (cur + rdlen > pkt_len) return 0;

        if (is_additional && type == 41 /* OPT */) {
            if (edns) {
                edns->present = true;
                edns->udp_payload_size = class_code;
                edns->ext_rcode = (uint8_t)((ttl >> 24) & 0xFF);
                edns->version = (uint8_t)((ttl >> 16) & 0xFF);
                edns->do_bit = (ttl & 0x8000) != 0;

                size_t opt_off = 0;
                while (opt_off + 4 <= rdlen) {
                    uint16_t opt_code = ((uint16_t)pkt[cur + opt_off] << 8) | pkt[cur + opt_off + 1];
                    uint16_t opt_len = ((uint16_t)pkt[cur + opt_off + 2] << 8) | pkt[cur + opt_off + 3];
                    opt_off += 4;
                    if (opt_off + opt_len > rdlen) break;

                    if (opt_code == 10 /* COOKIE */) {
                        edns->has_cookie = true;
                    } else if (opt_code == 8 /* ECS */) {
                        edns->has_ecs = true;
                        if (opt_len >= 4) {
                            edns->ecs_family = ((uint16_t)pkt[cur + opt_off] << 8) | pkt[cur + opt_off + 1];
                            edns->ecs_source_prefix = pkt[cur + opt_off + 2];
                            edns->ecs_scope_prefix = pkt[cur + opt_off + 3];
                            size_t alen = opt_len - 4;
                            if (alen > sizeof(edns->ecs_addr)) alen = sizeof(edns->ecs_addr);
                            memcpy(edns->ecs_addr, pkt + cur + opt_off + 4, alen);
                            edns->ecs_addr_len = alen;
                        }
                    } else {
                        if (edns->other_opts_len + 4 + opt_len <= sizeof(edns->other_opts)) {
                            edns->other_opts[edns->other_opts_len++] = (uint8_t)(opt_code >> 8);
                            edns->other_opts[edns->other_opts_len++] = (uint8_t)(opt_code & 0xFF);
                            edns->other_opts[edns->other_opts_len++] = (uint8_t)(opt_len >> 8);
                            edns->other_opts[edns->other_opts_len++] = (uint8_t)(opt_len & 0xFF);
                            memcpy(edns->other_opts + edns->other_opts_len, pkt + cur + opt_off, opt_len);
                            edns->other_opts_len += opt_len;
                        }
                    }
                    opt_off += opt_len;
                }
            }
            cur += rdlen;
            continue;
        }

        if (num_parsed < MAX_SECTION_RRS) {
            replay_rr_t *rr = &rrs[num_parsed++];
            memset(rr, 0, sizeof(*rr));
            rr->class_code = class_code;
            rr->type = type;
            rr->ttl = ttl;
            strncpy(rr->name, name, sizeof(rr->name) - 1);

            if (type == 5 /* CNAME */ || type == 2 /* NS */ || type == 12 /* PTR */ || type == 39 /* DNAME */) {
                expand_wire_name_buf(pkt, pkt_len, cur, NULL, (char *)rr->rdata, sizeof(rr->rdata));
                rr->rdlength = (uint16_t)strlen((char *)rr->rdata);
            } else if (type == 15 /* MX */ && rdlen >= 2) {
                rr->rdata[0] = pkt[cur];
                rr->rdata[1] = pkt[cur + 1];
                expand_wire_name_buf(pkt, pkt_len, cur + 2, NULL, (char *)rr->rdata + 2, sizeof(rr->rdata) - 2);
                rr->rdlength = (uint16_t)(2 + strlen((char *)rr->rdata + 2));
            } else {
                size_t cpy = rdlen < sizeof(rr->rdata) ? rdlen : sizeof(rr->rdata);
                memcpy(rr->rdata, pkt + cur, cpy);
                rr->rdlength = (uint16_t)cpy;
            }
        }
        cur += rdlen;
    }

    if (out_rr_count) *out_rr_count = num_parsed;
    return cur;
}

static int compare_replay_rr(const void *p1, const void *p2) {
    const replay_rr_t *r1 = (const replay_rr_t *)p1;
    const replay_rr_t *r2 = (const replay_rr_t *)p2;

    if (r1->class_code != r2->class_code) {
        return (int)r1->class_code - (int)r2->class_code;
    }
    if (r1->type != r2->type) {
        return (int)r1->type - (int)r2->type;
    }
    int nc = strcmp(r1->name, r2->name);
    if (nc != 0) return nc;

    if (r1->rdlength != r2->rdlength) {
        return (int)r1->rdlength - (int)r2->rdlength;
    }
    return memcmp(r1->rdata, r2->rdata, r1->rdlength);
}

static uint32_t compare_rr_sections(const replay_rr_t *r1, size_t n1,
                                    const replay_rr_t *r2, size_t n2,
                                    bool ignore_ttl, uint32_t base_flag) {
    uint32_t flags = 0;
    if (n1 != n2) {
        flags |= base_flag;
    }

    size_t min_n = (n1 < n2) ? n1 : n2;
    for (size_t i = 0; i < min_n; i++) {
        if (compare_replay_rr(&r1[i], &r2[i]) != 0) {
            flags |= base_flag;
            break;
        }
        if (!ignore_ttl && r1[i].ttl != r2[i].ttl) {
            flags |= base_flag;
            break;
        }
    }
    return flags;
}

static uint32_t compare_edns(const replay_edns_t *e1, const replay_edns_t *e2) {
    if (e1->present != e2->present) return DIFF_EDNS;
    if (!e1->present) return 0;

    uint32_t flags = 0;
    if (e1->udp_payload_size != e2->udp_payload_size) flags |= DIFF_EDNS;
    if (e1->ext_rcode != e2->ext_rcode) flags |= (DIFF_EDNS | DIFF_RCODE);
    if (e1->version != e2->version) flags |= DIFF_EDNS;
    if (e1->do_bit != e2->do_bit) flags |= DIFF_EDNS;
    if (e1->has_cookie != e2->has_cookie) flags |= DIFF_EDNS;
    if (e1->has_ecs != e2->has_ecs) {
        flags |= DIFF_EDNS;
    } else if (e1->has_ecs) {
        if (e1->ecs_family != e2->ecs_family ||
            e1->ecs_source_prefix != e2->ecs_source_prefix ||
            e1->ecs_scope_prefix != e2->ecs_scope_prefix ||
            e1->ecs_addr_len != e2->ecs_addr_len ||
            memcmp(e1->ecs_addr, e2->ecs_addr, e1->ecs_addr_len) != 0) {
            flags |= DIFF_EDNS;
        }
    }
    if (e1->other_opts_len != e2->other_opts_len ||
        memcmp(e1->other_opts, e2->other_opts, e1->other_opts_len) != 0) {
        flags |= DIFF_EDNS;
    }
    return flags;
}

void diff_dns_responses(const uint8_t *resp1, size_t len1, const uint8_t *resp2, size_t len2, bool ignore_ttl, diff_result_t *out_diff) {
    if (!out_diff) return;
    memset(out_diff, 0, sizeof(*out_diff));
    out_diff->match = true;
    out_diff->rcode_match = true;
    out_diff->flags_match = true;
    out_diff->ancount_match = true;
    out_diff->rrset_match = true;

    if (!resp1 && !resp2 && len1 < 12 && len2 < 12) return;
    if (!resp1 || !resp2 || len1 < 12 || len2 < 12) {
        out_diff->match = false;
        out_diff->diff_flags |= DIFF_RCODE;
        out_diff->rcode_match = false;
        snprintf(out_diff->diff_desc, sizeof(out_diff->diff_desc), "Length mismatch (truncated < 12 bytes or NULL)");
        return;
    }

    if (len1 == len2 && memcmp(resp1, resp2, len1) == 0) {
        snprintf(out_diff->diff_desc, sizeof(out_diff->diff_desc), "Identical");
        return;
    }

    uint8_t rcode1 = resp1[3] & 0x0F;
    uint8_t rcode2 = resp2[3] & 0x0F;
    if (rcode1 != rcode2) {
        out_diff->diff_flags |= DIFF_RCODE;
    }

    uint8_t flags1 = resp1[2] & 0x06; // AA (0x04) | TC (0x02)
    uint8_t flags2 = resp2[2] & 0x06;
    if (flags1 != flags2) {
        out_diff->diff_flags |= DIFF_FLAGS;
    }

    uint16_t ancount1 = ((uint16_t)resp1[6] << 8) | resp1[7];
    uint16_t ancount2 = ((uint16_t)resp2[6] << 8) | resp2[7];
    if (ancount1 != ancount2) {
        out_diff->diff_flags |= DIFF_ANCOUNT;
    }

    uint16_t nscount1 = ((uint16_t)resp1[8] << 8) | resp1[9];
    uint16_t nscount2 = ((uint16_t)resp2[8] << 8) | resp2[9];
    if (nscount1 != nscount2) {
        out_diff->diff_flags |= DIFF_NSCOUNT;
    }

    uint16_t arcount1 = ((uint16_t)resp1[10] << 8) | resp1[11];
    uint16_t arcount2 = ((uint16_t)resp2[10] << 8) | resp2[11];
    if (arcount1 != arcount2) {
        out_diff->diff_flags |= DIFF_ARCOUNT;
    }

    // Skip question section on both
    uint16_t qd1 = ((uint16_t)resp1[4] << 8) | resp1[5];
    uint16_t qd2 = ((uint16_t)resp2[4] << 8) | resp2[5];
    size_t off1 = 12;
    for (uint16_t i = 0; i < qd1 && off1 < len1; i++) {
        size_t next_off = 0;
        if (!expand_wire_name_buf(resp1, len1, off1, &next_off, NULL, 0)) { off1 = 0; break; }
        off1 = next_off + 4;
    }
    size_t off2 = 12;
    for (uint16_t i = 0; i < qd2 && off2 < len2; i++) {
        size_t next_off = 0;
        if (!expand_wire_name_buf(resp2, len2, off2, &next_off, NULL, 0)) { off2 = 0; break; }
        off2 = next_off + 4;
    }

    if (off1 == 0 || off2 == 0 || off1 > len1 || off2 > len2) {
        out_diff->diff_flags |= DIFF_ANSWER_RRSET;
        out_diff->match = false;
        snprintf(out_diff->diff_desc, sizeof(out_diff->diff_desc), "Malformed question section");
        return;
    }

    diff_scratch_t *sc = (diff_scratch_t *)malloc(sizeof(diff_scratch_t));
    if (!sc) {
        out_diff->match = false;
        snprintf(out_diff->diff_desc, sizeof(out_diff->diff_desc), "Memory allocation failed");
        return;
    }
    memset(sc, 0, sizeof(*sc));

    size_t num_ans1 = 0, num_ans2 = 0;
    off1 = parse_section_rrs(resp1, len1, off1, ancount1, false, sc->ans1, &num_ans1, NULL);
    off2 = parse_section_rrs(resp2, len2, off2, ancount2, false, sc->ans2, &num_ans2, NULL);
    if (off1 == 0 || off2 == 0) {
        out_diff->diff_flags |= DIFF_ANSWER_RRSET;
    }

    size_t num_auth1 = 0, num_auth2 = 0;
    off1 = parse_section_rrs(resp1, len1, off1, nscount1, false, sc->auth1, &num_auth1, NULL);
    off2 = parse_section_rrs(resp2, len2, off2, nscount2, false, sc->auth2, &num_auth2, NULL);
    if (off1 == 0 || off2 == 0) {
        out_diff->diff_flags |= DIFF_AUTH_RRSET;
    }

    size_t num_add1 = 0, num_add2 = 0;
    off1 = parse_section_rrs(resp1, len1, off1, arcount1, true, sc->add1, &num_add1, &sc->edns1);
    off2 = parse_section_rrs(resp2, len2, off2, arcount2, true, sc->add2, &num_add2, &sc->edns2);
    if (off1 == 0 || off2 == 0) {
        out_diff->diff_flags |= DIFF_ADD_RRSET;
    }

    qsort(sc->ans1, num_ans1, sizeof(replay_rr_t), compare_replay_rr);
    qsort(sc->ans2, num_ans2, sizeof(replay_rr_t), compare_replay_rr);

    qsort(sc->auth1, num_auth1, sizeof(replay_rr_t), compare_replay_rr);
    qsort(sc->auth2, num_auth2, sizeof(replay_rr_t), compare_replay_rr);

    qsort(sc->add1, num_add1, sizeof(replay_rr_t), compare_replay_rr);
    qsort(sc->add2, num_add2, sizeof(replay_rr_t), compare_replay_rr);

    char ns_targets[32][MAX_NAME_BUF];
    size_t ns_target_count = 0;
    for (size_t i = 0; i < num_auth1 && ns_target_count < 32; i++) {
        if (sc->auth1[i].type == 2 /* NS */) {
            strncpy(ns_targets[ns_target_count++], (char *)sc->auth1[i].rdata, MAX_NAME_BUF - 1);
        }
    }
    for (size_t i = 0; i < num_auth2 && ns_target_count < 32; i++) {
        if (sc->auth2[i].type == 2 /* NS */) {
            bool found = false;
            for (size_t j = 0; j < ns_target_count; j++) {
                if (strcmp(ns_targets[j], (char *)sc->auth2[i].rdata) == 0) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                strncpy(ns_targets[ns_target_count++], (char *)sc->auth2[i].rdata, MAX_NAME_BUF - 1);
            }
        }
    }

    uint32_t ans_diff = compare_rr_sections(sc->ans1, num_ans1, sc->ans2, num_ans2, ignore_ttl, DIFF_ANSWER_RRSET);
    out_diff->diff_flags |= ans_diff;

    uint32_t auth_diff = compare_rr_sections(sc->auth1, num_auth1, sc->auth2, num_auth2, ignore_ttl, DIFF_AUTH_RRSET);
    out_diff->diff_flags |= auth_diff;

    uint32_t add_diff = compare_rr_sections(sc->add1, num_add1, sc->add2, num_add2, ignore_ttl, DIFF_ADD_RRSET);
    out_diff->diff_flags |= add_diff;

    uint32_t edns_diff = compare_edns(&sc->edns1, &sc->edns2);
    out_diff->diff_flags |= edns_diff;

    if (ans_diff != 0) {
        bool has_cname = false;
        for (size_t i = 0; i < num_ans1; i++) {
            if (sc->ans1[i].type == 5 /* CNAME */) { has_cname = true; break; }
        }
        if (!has_cname) {
            for (size_t i = 0; i < num_ans2; i++) {
                if (sc->ans2[i].type == 5 /* CNAME */) { has_cname = true; break; }
            }
        }
        if (has_cname) {
            out_diff->diff_flags |= DIFF_CNAME_CHAIN;
        }
    }

    if (ans_diff || auth_diff || add_diff) {
        replay_rr_t *all1[] = { sc->ans1, sc->auth1, sc->add1 };
        size_t n1_arr[] = { num_ans1, num_auth1, num_add1 };
        replay_rr_t *all2[] = { sc->ans2, sc->auth2, sc->add2 };
        size_t n2_arr[] = { num_ans2, num_auth2, num_add2 };

        for (int sec = 0; sec < 3; sec++) {
            replay_rr_t *s1 = all1[sec];
            size_t count1 = n1_arr[sec];
            replay_rr_t *s2 = all2[sec];
            size_t count2 = n2_arr[sec];

            for (size_t i = 0; i < count1; i++) {
                if (s1[i].type == 46 /* RRSIG */) {
                    bool found = false;
                    for (size_t j = 0; j < count2; j++) {
                        if (compare_replay_rr(&s1[i], &s2[j]) == 0 && (ignore_ttl || s1[i].ttl == s2[j].ttl)) {
                            found = true; break;
                        }
                    }
                    if (!found) out_diff->diff_flags |= DIFF_DNSSEC_RRSIG;
                } else if (s1[i].type == 47 /* NSEC */ || s1[i].type == 50 /* NSEC3 */) {
                    bool found = false;
                    for (size_t j = 0; j < count2; j++) {
                        if (compare_replay_rr(&s1[i], &s2[j]) == 0 && (ignore_ttl || s1[i].ttl == s2[j].ttl)) {
                            found = true; break;
                        }
                    }
                    if (!found) out_diff->diff_flags |= DIFF_DNSSEC_NSEC;
                }
            }

            for (size_t i = 0; i < count2; i++) {
                if (s2[i].type == 46 /* RRSIG */) {
                    bool found = false;
                    for (size_t j = 0; j < count1; j++) {
                        if (compare_replay_rr(&s2[i], &s1[j]) == 0 && (ignore_ttl || s2[i].ttl == s1[j].ttl)) {
                            found = true; break;
                        }
                    }
                    if (!found) out_diff->diff_flags |= DIFF_DNSSEC_RRSIG;
                } else if (s2[i].type == 47 /* NSEC */ || s2[i].type == 50 /* NSEC3 */) {
                    bool found = false;
                    for (size_t j = 0; j < count1; j++) {
                        if (compare_replay_rr(&s2[i], &s1[j]) == 0 && (ignore_ttl || s2[i].ttl == s1[j].ttl)) {
                            found = true; break;
                        }
                    }
                    if (!found) out_diff->diff_flags |= DIFF_DNSSEC_NSEC;
                }
            }
        }
    }

    if (add_diff != 0) {
        for (size_t i = 0; i < num_add1; i++) {
            if (sc->add1[i].type == 1 /* A */ || sc->add1[i].type == 28 /* AAAA */) {
                bool found = false;
                for (size_t j = 0; j < num_add2; j++) {
                    if (compare_replay_rr(&sc->add1[i], &sc->add2[j]) == 0 && (ignore_ttl || sc->add1[i].ttl == sc->add2[j].ttl)) {
                        found = true; break;
                    }
                }
                if (!found) {
                    for (size_t k = 0; k < ns_target_count; k++) {
                        if (strcmp(sc->add1[i].name, ns_targets[k]) == 0) {
                            out_diff->diff_flags |= DIFF_GLUE_MISSING;
                            break;
                        }
                    }
                }
            }
        }
        for (size_t i = 0; i < num_add2; i++) {
            if (sc->add2[i].type == 1 /* A */ || sc->add2[i].type == 28 /* AAAA */) {
                bool found = false;
                for (size_t j = 0; j < num_add1; j++) {
                    if (compare_replay_rr(&sc->add2[i], &sc->add1[j]) == 0 && (ignore_ttl || sc->add2[i].ttl == sc->add1[j].ttl)) {
                        found = true; break;
                    }
                }
                if (!found) {
                    for (size_t k = 0; k < ns_target_count; k++) {
                        if (strcmp(sc->add2[i].name, ns_targets[k]) == 0) {
                            out_diff->diff_flags |= DIFF_GLUE_MISSING;
                            break;
                        }
                    }
                }
            }
        }
    }

    free(sc);

    if (out_diff->diff_flags == 0) {
        out_diff->match = true;
        snprintf(out_diff->diff_desc, sizeof(out_diff->diff_desc), "Identical");
    } else {
        out_diff->match = false;
        char buf[512] = "";
        size_t bpos = 0;
        #define APPEND_DIFF_FLAG(flg, name) do { \
            if (out_diff->diff_flags & (flg)) { \
                bpos += snprintf(buf + bpos, sizeof(buf) - bpos, "[%s] ", name); \
            } \
        } while (0)

        APPEND_DIFF_FLAG(DIFF_RCODE, "RCODE");
        APPEND_DIFF_FLAG(DIFF_FLAGS, "FLAGS");
        APPEND_DIFF_FLAG(DIFF_ANCOUNT, "ANCOUNT");
        APPEND_DIFF_FLAG(DIFF_NSCOUNT, "NSCOUNT");
        APPEND_DIFF_FLAG(DIFF_ARCOUNT, "ARCOUNT");
        APPEND_DIFF_FLAG(DIFF_ANSWER_RRSET, "ANSWER");
        APPEND_DIFF_FLAG(DIFF_AUTH_RRSET, "AUTH");
        APPEND_DIFF_FLAG(DIFF_ADD_RRSET, "ADDITIONAL");
        APPEND_DIFF_FLAG(DIFF_GLUE_MISSING, "GLUE_MISSING");
        APPEND_DIFF_FLAG(DIFF_EDNS, "EDNS");
        APPEND_DIFF_FLAG(DIFF_DNSSEC_RRSIG, "DNSSEC_RRSIG");
        APPEND_DIFF_FLAG(DIFF_DNSSEC_NSEC, "DNSSEC_NSEC");
        APPEND_DIFF_FLAG(DIFF_CNAME_CHAIN, "CNAME_CHAIN");
        #undef APPEND_DIFF_FLAG

        snprintf(out_diff->diff_desc, sizeof(out_diff->diff_desc), "Diff: %s", buf);
    }

    out_diff->rcode_match = !(out_diff->diff_flags & DIFF_RCODE);
    out_diff->flags_match = !(out_diff->diff_flags & DIFF_FLAGS);
    out_diff->ancount_match = !(out_diff->diff_flags & DIFF_ANCOUNT);
    out_diff->rrset_match = !(out_diff->diff_flags & (DIFF_ANSWER_RRSET | DIFF_AUTH_RRSET | DIFF_ADD_RRSET));
    out_diff->glue_missing = (out_diff->diff_flags & DIFF_GLUE_MISSING) != 0;
    out_diff->edns_diff = (out_diff->diff_flags & DIFF_EDNS) != 0;
    out_diff->dnssec_rrsig_diff = (out_diff->diff_flags & DIFF_DNSSEC_RRSIG) != 0;
    out_diff->dnssec_nsec_diff = (out_diff->diff_flags & DIFF_DNSSEC_NSEC) != 0;
    out_diff->cname_chain_diff = (out_diff->diff_flags & DIFF_CNAME_CHAIN) != 0;
}

static inline void replay_sleep_us(uint32_t us) {
    if (us == 0) return;
#ifdef _WIN32
    Sleep((DWORD)((us + 999) / 1000));
#else
    usleep((useconds_t)us);
#endif
}

static inline void set_replay_socket_timeouts(int sock, int timeout_ms) {
    if (timeout_ms <= 0) timeout_ms = 2000;
#ifdef _WIN32
    DWORD tv = (DWORD)timeout_ms;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

static ssize_t replay_exchange_posix(const char *server, int port, bool use_tcp,
                                     const uint8_t *pkt, size_t pkt_len,
                                     uint8_t *resp, size_t resp_cap, int timeout_ms) {
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    socklen_t slen = 0;

    struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
    if (inet_pton(AF_INET, server, &sin->sin_addr) == 1) {
        sin->sin_family = AF_INET;
        sin->sin_port = htons(port > 0 ? port : 53);
        slen = sizeof(*sin);
    } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
        if (inet_pton(AF_INET6, server, &sin6->sin6_addr) == 1) {
            sin6->sin6_family = AF_INET6;
            sin6->sin6_port = htons(port > 0 ? port : 53);
            slen = sizeof(*sin6);
        } else {
            struct addrinfo hints, *res = NULL;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = use_tcp ? SOCK_STREAM : SOCK_DGRAM;
            char pbuf[16];
            snprintf(pbuf, sizeof(pbuf), "%d", port > 0 ? port : 53);
            if (getaddrinfo(server, pbuf, &hints, &res) == 0 && res != NULL) {
                if (res->ai_addrlen <= sizeof(ss)) {
                    memcpy(&ss, res->ai_addr, res->ai_addrlen);
                    slen = (socklen_t)res->ai_addrlen;
                    freeaddrinfo(res);
                } else {
                    freeaddrinfo(res);
                    return -1;
                }
            } else {
                if (res) freeaddrinfo(res);
                return -1;
            }
        }
    }

    if (!use_tcp) {
        int fd = socket(ss.ss_family, SOCK_DGRAM, 0);
        if (fd < 0) return -1;
        set_replay_socket_timeouts(fd, timeout_ms);

        ssize_t sent = sendto(fd, pkt, pkt_len, 0, (struct sockaddr *)&ss, slen);
        if (sent != (ssize_t)pkt_len) {
            close(fd);
            return -1;
        }
        ssize_t received = recvfrom(fd, resp, resp_cap, 0, NULL, NULL);
        close(fd);
        return received;
    } else {
        int fd = socket(ss.ss_family, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        set_replay_socket_timeouts(fd, timeout_ms);

        if (connect(fd, (struct sockaddr *)&ss, slen) != 0) {
            close(fd);
            return -1;
        }
        uint8_t len_prefix[2] = { (uint8_t)(pkt_len >> 8), (uint8_t)(pkt_len & 0xFF) };
        if (send(fd, len_prefix, 2, 0) != 2 || send(fd, pkt, pkt_len, 0) != (ssize_t)pkt_len) {
            close(fd);
            return -1;
        }
        uint8_t rlen_buf[2];
        size_t got_len = 0;
        while (got_len < 2) {
            ssize_t n = recv(fd, rlen_buf + got_len, 2 - got_len, 0);
            if (n <= 0) {
                close(fd);
                return -1;
            }
            got_len += (size_t)n;
        }
        uint16_t expected_len = ((uint16_t)rlen_buf[0] << 8) | rlen_buf[1];
        if (expected_len > resp_cap) expected_len = (uint16_t)resp_cap;
        ssize_t total = 0;
        while (total < expected_len) {
            ssize_t r = recv(fd, resp + total, expected_len - total, 0);
            if (r <= 0) break;
            total += r;
        }
        close(fd);
        return total;
    }
}

static ssize_t replay_exchange(const char *server, int port, const char *transport,
                               const uint8_t *pkt, size_t pkt_len,
                               uint8_t *resp, size_t resp_cap, int timeout_ms) {
    bool use_tcp = (transport && strcasecmp(transport, "tcp") == 0);
    return replay_exchange_posix(server, port, use_tcp, pkt, pkt_len, resp, resp_cap, timeout_ms);
}

static void *replay_worker_func(void *arg) {
    worker_shared_t *ws = (worker_shared_t *)arg;
    replay_queue_t *q = ws->queue;
    const replay_options_t *opts = ws->opts;

    while (1) {
        replay_task_t task;
        pthread_mutex_lock(&q->lock);
        while (q->count == 0 && !q->done) {
            pthread_cond_wait(&q->not_empty, &q->lock);
        }
        if (q->count == 0 && q->done) {
            pthread_mutex_unlock(&q->lock);
            break;
        }
        if (opts->stop_after > 0) {
            pthread_mutex_lock(&ws->stats_lock);
            uint64_t diff_cnt = ws->diff_stats.total_compared - ws->diff_stats.identical;
            pthread_mutex_unlock(&ws->stats_lock);
            if (diff_cnt >= (uint64_t)opts->stop_after) {
                q->count = 0;
                q->done = true;
                pthread_cond_broadcast(&q->not_empty);
                pthread_mutex_unlock(&q->lock);
                break;
            }
        }
        task = q->tasks[q->head];
        q->head = (q->head + 1) % REPLAY_QUEUE_CAPACITY;
        q->count--;
        pthread_cond_signal(&q->not_full);
        pthread_mutex_unlock(&q->lock);

        const char *t1 = opts->server1_transport[0] ? opts->server1_transport :
                         (opts->transport_explicit ? opts->transport :
                          (task.transport[0] ? task.transport : opts->transport));
        int tmo = opts->timeout_ms > 0 ? opts->timeout_ms : 2000;

        // Server 1 query
        uint8_t resp1[4096];
        struct timespec ts1_start, ts1_end;
        clock_gettime(CLOCK_MONOTONIC, &ts1_start);
        ssize_t r1 = replay_exchange(opts->server1_host, opts->server1_port, t1,
                                     task.pkt, task.pkt_len, resp1, sizeof(resp1), tmo);
        clock_gettime(CLOCK_MONOTONIC, &ts1_end);
        double rtt1_ms = (ts1_end.tv_sec - ts1_start.tv_sec) * 1000.0 +
                         (ts1_end.tv_nsec - ts1_start.tv_nsec) / 1000000.0;

        uint8_t resp2[4096];
        ssize_t r2 = -1;
        double rtt2_ms = 0.0;
        if (opts->has_server2) {
            const char *t2 = opts->server2_transport[0] ? opts->server2_transport :
                             (opts->transport_explicit ? opts->transport :
                              (task.transport[0] ? task.transport : opts->transport));
            struct timespec ts2_start, ts2_end;
            clock_gettime(CLOCK_MONOTONIC, &ts2_start);
            r2 = replay_exchange(opts->server2_host, opts->server2_port, t2,
                                 task.pkt, task.pkt_len, resp2, sizeof(resp2), tmo);
            clock_gettime(CLOCK_MONOTONIC, &ts2_end);
            rtt2_ms = (ts2_end.tv_sec - ts2_start.tv_sec) * 1000.0 +
                      (ts2_end.tv_nsec - ts2_start.tv_nsec) / 1000000.0;
        } else if (opts->compare_recorded && task.has_recorded_resp) {
            size_t cp = task.recorded_resp_len > sizeof(resp2) ? sizeof(resp2) : task.recorded_resp_len;
            memcpy(resp2, task.recorded_resp, cp);
            r2 = (ssize_t)cp;
            rtt2_ms = 0.0;
        }

        diff_result_t diff;
        memset(&diff, 0, sizeof(diff));
        if (opts->has_server2 || opts->compare_recorded) {
            if (r1 > 0 && r2 > 0) {
                diff_dns_responses(resp1, (size_t)r1, resp2, (size_t)r2, opts->ignore_ttl, &diff);
            } else if (r1 <= 0 && r2 <= 0) {
                diff.match = true;
            } else {
                diff.match = false;
                diff.diff_flags |= DIFF_RCODE;
                snprintf(diff.diff_desc, sizeof(diff.diff_desc), "Reachability mismatch: Live=%s Recorded/S2=%s",
                         r1 > 0 ? "OK" : "TIMEOUT", r2 > 0 ? "OK" : (opts->compare_recorded ? "N/A" : "TIMEOUT"));
            }
        }

        pthread_mutex_lock(&ws->stats_lock);
        ws->s1_stats.queries_sent++;
        if (r1 > 0) {
            ws->s1_stats.responses_received++;
            ws->s1_stats.total_rtt_ms += rtt1_ms;
            if (r1 >= 4) {
                uint8_t rcode = resp1[3] & 0x0F;
                ws->s1_stats.rcode_counts[rcode]++;
            }
        } else {
            ws->s1_stats.timeouts++;
        }

        if (opts->has_server2 || opts->compare_recorded) {
            ws->s2_stats.queries_sent++;
            if (r2 > 0) {
                ws->s2_stats.responses_received++;
                ws->s2_stats.total_rtt_ms += rtt2_ms;
                if (r2 >= 4) {
                    uint8_t rcode = resp2[3] & 0x0F;
                    ws->s2_stats.rcode_counts[rcode]++;
                }
            } else {
                ws->s2_stats.timeouts++;
            }

            ws->diff_stats.total_compared++;
            if (diff.match) {
                ws->diff_stats.identical++;
            } else {
                if (diff.diff_flags & DIFF_RCODE) ws->diff_stats.rcode_mismatches++;
                if (diff.diff_flags & DIFF_FLAGS) ws->diff_stats.flags_mismatches++;
                if (diff.diff_flags & (DIFF_ANCOUNT | DIFF_NSCOUNT | DIFF_ARCOUNT)) ws->diff_stats.ancount_mismatches++;
                if (diff.diff_flags & (DIFF_ANSWER_RRSET | DIFF_AUTH_RRSET | DIFF_ADD_RRSET)) ws->diff_stats.rrset_mismatches++;
                if (diff.diff_flags & DIFF_GLUE_MISSING) ws->diff_stats.glue_missing_diffs++;
                if (diff.diff_flags & DIFF_EDNS) ws->diff_stats.edns_diffs++;
                if (diff.diff_flags & DIFF_DNSSEC_RRSIG) ws->diff_stats.dnssec_rrsig_diffs++;
                if (diff.diff_flags & DIFF_DNSSEC_NSEC) ws->diff_stats.dnssec_nsec_diffs++;
                if (diff.diff_flags & DIFF_CNAME_CHAIN) ws->diff_stats.cname_chain_diffs++;

                if (ws->opts->diff_fp) {
                    fprintf(ws->opts->diff_fp, "[DIFF #%lu] %s (flags=0x%04x)\n",
                            (unsigned long)task.seq, diff.diff_desc, diff.diff_flags);
                    fflush(ws->opts->diff_fp);
                } else if (!opts->output_json && ws->diff_stats.total_compared <= 10) {
                    fprintf(stderr, "[DIFF #%lu] %s\n", (unsigned long)task.seq, diff.diff_desc);
                }

                if (opts->stop_after > 0) {
                    uint64_t diff_cnt = ws->diff_stats.total_compared - ws->diff_stats.identical;
                    if (diff_cnt >= (uint64_t)opts->stop_after) {
                        pthread_mutex_unlock(&ws->stats_lock);
                        pthread_mutex_lock(&q->lock);
                        q->count = 0;
                        q->done = true;
                        pthread_cond_broadcast(&q->not_empty);
                        pthread_mutex_unlock(&q->lock);
                        pthread_mutex_lock(&ws->stats_lock);
                    }
                }
            }
        }
        pthread_mutex_unlock(&ws->stats_lock);
    }
    return NULL;
}

static void parse_host_port(const char *arg, char *out_host, size_t host_cap, int *out_port) {
    *out_port = 53;
    if (!arg) return;
    const char *colon = strchr(arg, ':');
    if (colon) {
        size_t hlen = colon - arg;
        if (hlen >= host_cap) hlen = host_cap - 1;
        strncpy(out_host, arg, hlen);
        out_host[hlen] = '\0';
        *out_port = atoi(colon + 1);
    } else {
        strncpy(out_host, arg, host_cap - 1);
        out_host[host_cap - 1] = '\0';
    }
}

static bool enqueue_task_full(replay_queue_t *q, const uint8_t *pkt, size_t len, uint64_t seq,
                              const char *transport,
                              const uint8_t *recorded_resp, size_t recorded_resp_len) {
    if (!pkt || len == 0 || len > MAX_REPLAY_PACKET_LEN) return false;
    pthread_mutex_lock(&q->lock);
    while (q->count >= REPLAY_QUEUE_CAPACITY && !q->done) {
        pthread_cond_wait(&q->not_full, &q->lock);
    }
    if (q->done) {
        pthread_mutex_unlock(&q->lock);
        return false;
    }
    replay_task_t *t = &q->tasks[q->tail];
    memcpy(t->pkt, pkt, len);
    t->pkt_len = len;
    t->seq = seq;
    if (transport && transport[0]) {
        strncpy(t->transport, transport, sizeof(t->transport) - 1);
        t->transport[sizeof(t->transport) - 1] = '\0';
    } else {
        t->transport[0] = '\0';
    }
    if (recorded_resp && recorded_resp_len > 0) {
        size_t cp = recorded_resp_len > sizeof(t->recorded_resp) ? sizeof(t->recorded_resp) : recorded_resp_len;
        memcpy(t->recorded_resp, recorded_resp, cp);
        t->recorded_resp_len = cp;
        t->has_recorded_resp = true;
    } else {
        t->recorded_resp_len = 0;
        t->has_recorded_resp = false;
    }
    q->tail = (q->tail + 1) % REPLAY_QUEUE_CAPACITY;
    q->count++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
    return true;
}

static bool enqueue_task(replay_queue_t *q, const uint8_t *pkt, size_t len, uint64_t seq, const char *transport) {
    return enqueue_task_full(q, pkt, len, seq, transport, NULL, 0);
}

#define PAIR_TABLE_SIZE 4096

typedef struct {
    bool in_use;
    uint8_t addr_key[32];
    uint16_t port_key[2];
    uint16_t txid;
    uint8_t protocol;
    bool has_query;
    uint8_t query_wire[MAX_REPLAY_PACKET_LEN];
    size_t query_wire_len;
    char query_transport[16];
    bool has_response;
    uint8_t response_wire[MAX_REPLAY_PACKET_LEN];
    size_t response_wire_len;
} dns_pair_slot_t;

typedef struct {
    dns_pair_slot_t slots[PAIR_TABLE_SIZE];
} dns_pair_table_t;

static uint32_t hash_pair_key(const uint8_t *addr_key, const uint16_t *port_key, uint16_t txid, uint8_t proto) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < 32; i++) {
        h ^= addr_key[i];
        h *= 16777619u;
    }
    h ^= (uint8_t)(port_key[0] >> 8); h *= 16777619u;
    h ^= (uint8_t)(port_key[0] & 0xFF); h *= 16777619u;
    h ^= (uint8_t)(port_key[1] >> 8); h *= 16777619u;
    h ^= (uint8_t)(port_key[1] & 0xFF); h *= 16777619u;
    h ^= (uint8_t)(txid >> 8); h *= 16777619u;
    h ^= (uint8_t)(txid & 0xFF); h *= 16777619u;
    h ^= proto; h *= 16777619u;
    return h;
}

static bool dns_pair_table_feed_wire(dns_pair_table_t *table,
                                     const uint8_t *addr_key, const uint16_t *port_key,
                                     uint8_t protocol, const char *transport,
                                     const uint8_t *wire, size_t wire_len,
                                     replay_queue_t *queue, uint64_t *seq_ptr,
                                     const replay_options_t *opts, worker_shared_t *ws) {
    if (!table || !wire || wire_len < 12 || wire_len > MAX_REPLAY_PACKET_LEN) return true;

    uint16_t txid = ((uint16_t)wire[0] << 8) | wire[1];
    bool is_response = (wire[2] & 0x80) != 0;

    uint32_t h = hash_pair_key(addr_key, port_key, txid, protocol);
    size_t start_slot = h % PAIR_TABLE_SIZE;
    dns_pair_slot_t *slot = NULL;
    dns_pair_slot_t *empty_slot = NULL;

    for (size_t i = 0; i < PAIR_TABLE_SIZE; i++) {
        size_t idx = (start_slot + i) % PAIR_TABLE_SIZE;
        dns_pair_slot_t *s = &table->slots[idx];
        if (s->in_use) {
            if (s->protocol == protocol && s->txid == txid &&
                s->port_key[0] == port_key[0] && s->port_key[1] == port_key[1] &&
                memcmp(s->addr_key, addr_key, 32) == 0) {
                slot = s;
                break;
            }
        } else if (!empty_slot) {
            empty_slot = s;
        }
    }

    if (!slot) {
        if (!empty_slot) return true; // Table full, drop best-effort
        slot = empty_slot;
        slot->in_use = true;
        memcpy(slot->addr_key, addr_key, 32);
        slot->port_key[0] = port_key[0];
        slot->port_key[1] = port_key[1];
        slot->txid = txid;
        slot->protocol = protocol;
    }

    if (is_response) {
        memcpy(slot->response_wire, wire, wire_len);
        slot->response_wire_len = wire_len;
        slot->has_response = true;
    } else {
        uint16_t qdcount = ((uint16_t)wire[4] << 8) | wire[5];
        if (qdcount > 0) {
            memcpy(slot->query_wire, wire, wire_len);
            slot->query_wire_len = wire_len;
            if (transport && transport[0]) {
                strncpy(slot->query_transport, transport, sizeof(slot->query_transport) - 1);
                slot->query_transport[sizeof(slot->query_transport) - 1] = '\0';
            } else {
                slot->query_transport[0] = '\0';
            }
            slot->has_query = true;
        }
    }

    if (slot->has_query && slot->has_response) {
        (*seq_ptr)++;
        uint64_t cur_seq = *seq_ptr;
        uint8_t q_wire[MAX_REPLAY_PACKET_LEN];
        size_t q_len = slot->query_wire_len;
        memcpy(q_wire, slot->query_wire, q_len);
        char q_trans[16];
        strncpy(q_trans, slot->query_transport, sizeof(q_trans) - 1);
        q_trans[sizeof(q_trans) - 1] = '\0';
        uint8_t r_wire[MAX_REPLAY_PACKET_LEN];
        size_t r_len = slot->response_wire_len;
        memcpy(r_wire, slot->response_wire, r_len);

        memset(slot, 0, sizeof(*slot));

        if (!enqueue_task_full(queue, q_wire, q_len, cur_seq, q_trans, r_wire, r_len)) {
            return false;
        }
        if (opts->max_queries > 0 && (int)cur_seq >= opts->max_queries) {
            return false;
        }
        if (opts->stop_after > 0 && ws) {
            pthread_mutex_lock(&ws->stats_lock);
            uint64_t diff_cnt = ws->diff_stats.total_compared - ws->diff_stats.identical;
            pthread_mutex_unlock(&ws->stats_lock);
            if (diff_cnt >= (uint64_t)opts->stop_after) {
                pthread_mutex_lock(&queue->lock);
                queue->count = 0;
                queue->done = true;
                pthread_cond_broadcast(&queue->not_empty);
                pthread_mutex_unlock(&queue->lock);
                return false;
            }
        }
        if (opts->rate_qps > 0) {
            uint32_t rate_delay_us = (uint32_t)(1000000 / opts->rate_qps);
            replay_sleep_us(rate_delay_us);
        }
    }
    return true;
}

static void dns_pair_table_flush_incomplete(dns_pair_table_t *table, uint64_t *out_missing_count) {
    if (!table) return;
    uint64_t missing = 0;
    for (size_t i = 0; i < PAIR_TABLE_SIZE; i++) {
        dns_pair_slot_t *s = &table->slots[i];
        if (s->in_use) {
            if (s->has_query && !s->has_response) {
                missing++;
            }
            memset(s, 0, sizeof(*s));
        }
    }
    if (out_missing_count) *out_missing_count = missing;
}

typedef struct {
    dns_pair_table_t *pairs;
    replay_queue_t *queue;
    uint64_t *seq_ptr;
    const replay_options_t *opts;
    worker_shared_t *ws;
} tcp_reasm_cb_ctx_t;

static void tcp_reasm_dns_cb(void *user_ctx, uint32_t stream_id, int direction,
                             const uint8_t *addr_key, const uint16_t *port_key,
                             const uint8_t *dns_msg, size_t dns_msg_len) {
    (void)stream_id;
    (void)direction;
    tcp_reasm_cb_ctx_t *ctx = (tcp_reasm_cb_ctx_t *)user_ctx;
    if (!ctx) return;
    dns_pair_table_feed_wire(ctx->pairs, addr_key, port_key, 6 /* IPPROTO_TCP */,
                             "tcp", dns_msg, dns_msg_len,
                             ctx->queue, ctx->seq_ptr, ctx->opts, ctx->ws);
}

static size_t build_text_query(const char *qname, uint16_t qtype, bool dnssec_ok, uint8_t *buf, size_t cap) {
    if (cap < 64) return 0;
    memset(buf, 0, 12);
    buf[0] = (uint8_t)(rand() & 0xFF);
    buf[1] = (uint8_t)(rand() & 0xFF);
    buf[2] = 0x01; // RD = 1
    buf[5] = 1;    // QDCOUNT = 1
    if (dnssec_ok) {
        buf[11] = 1; // ARCOUNT = 1 (EDNS OPT)
    }

    size_t off = 12;
    const char *p = qname;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t lablen = dot ? (size_t)(dot - p) : strlen(p);
        if (lablen == 0) break;
        if (off + 1 + lablen >= cap) return 0;
        buf[off++] = (uint8_t)lablen;
        memcpy(buf + off, p, lablen);
        off += lablen;
        if (!dot) break;
        p = dot + 1;
    }
    if (off >= cap) return 0;
    buf[off++] = 0; // Root label

    if (off + 4 > cap) return 0;
    buf[off++] = (uint8_t)(qtype >> 8);
    buf[off++] = (uint8_t)(qtype & 0xFF);
    buf[off++] = 0x00; // IN class
    buf[off++] = 0x01;

    if (dnssec_ok) {
        if (off + 11 > cap) return 0;
        buf[off++] = 0x00; // Root name for OPT
        buf[off++] = 0x00; // Type OPT (41) high
        buf[off++] = 0x29; // Type OPT (41) low
        buf[off++] = 0x10; // UDP payload size (4096) high
        buf[off++] = 0x00; // UDP payload size low
        buf[off++] = 0x00; // Extended RCODE (0)
        buf[off++] = 0x00; // EDNS Version (0)
        buf[off++] = 0x80; // Flags: DO (DNSSEC OK) bit = 1 (0x8000)
        buf[off++] = 0x00; // Flags low
        buf[off++] = 0x00; // RDLENGTH high (0)
        buf[off++] = 0x00; // RDLENGTH low (0)
    }

    return off;
}

#ifndef _WIN32
__attribute__((noinline))
#endif
int run_replay_mode(int argc, char **argv) {
    replay_options_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.server1_port = 53;
    opts.server2_port = 53;
    opts.num_workers = 1;
    strncpy(opts.transport, "udp", sizeof(opts.transport) - 1);

    int idx = 0;
    while (idx < argc) {
        if (strcmp(argv[idx], "--replay") == 0) {
            if (idx + 1 < argc) {
                strncpy(opts.input_path, argv[++idx], sizeof(opts.input_path) - 1);
            }
        } else if (strcmp(argv[idx], "--server1") == 0) {
            if (idx + 1 < argc) {
                parse_host_port(argv[++idx], opts.server1_host, sizeof(opts.server1_host), &opts.server1_port);
            }
        } else if (strcmp(argv[idx], "--server2") == 0) {
            if (idx + 1 < argc) {
                parse_host_port(argv[++idx], opts.server2_host, sizeof(opts.server2_host), &opts.server2_port);
                opts.has_server2 = true;
                opts.do_diff = true;
            }
        } else if (strcmp(argv[idx], "--compare-recorded") == 0) {
            opts.compare_recorded = true;
            opts.do_diff = true;
        } else if (strcmp(argv[idx], "--server1-transport") == 0) {
            if (idx + 1 < argc) {
                strncpy(opts.server1_transport, argv[++idx], sizeof(opts.server1_transport) - 1);
            }
        } else if (strcmp(argv[idx], "--server2-transport") == 0) {
            if (idx + 1 < argc) {
                strncpy(opts.server2_transport, argv[++idx], sizeof(opts.server2_transport) - 1);
            }
        } else if (strcmp(argv[idx], "--rate") == 0 || strcmp(argv[idx], "--rate-limit") == 0) {
            if (idx + 1 < argc) {
                opts.rate_qps = atoi(argv[++idx]);
            }
        } else if (strcmp(argv[idx], "--workers") == 0 || strcmp(argv[idx], "--concurrency") == 0) {
            if (idx + 1 < argc) {
                opts.num_workers = atoi(argv[++idx]);
                if (opts.num_workers < 1) opts.num_workers = 1;
                if (opts.num_workers > 64) opts.num_workers = 64;
            }
        } else if (strcmp(argv[idx], "--diff") == 0) {
            opts.do_diff = true;
        } else if (strcmp(argv[idx], "--ignore-ttl") == 0) {
            opts.ignore_ttl = true;
        } else if (strcmp(argv[idx], "--timeout-ms") == 0) {
            if (idx + 1 < argc) {
                opts.timeout_ms = atoi(argv[++idx]);
            }
        } else if (strcmp(argv[idx], "--stop-after") == 0) {
            if (idx + 1 < argc) {
                opts.stop_after = atoi(argv[++idx]);
            }
        } else if (strcmp(argv[idx], "--output-diff") == 0) {
            if (idx + 1 < argc) {
                strncpy(opts.output_diff_path, argv[++idx], sizeof(opts.output_diff_path) - 1);
            }
        } else if (strcmp(argv[idx], "--output") == 0 || strcmp(argv[idx], "--output-format") == 0) {
            if (idx + 1 < argc) {
                idx++;
                if (strcasecmp(argv[idx], "json") == 0) opts.output_json = true;
            }
        } else if (strcmp(argv[idx], "--transport") == 0) {
            if (idx + 1 < argc) {
                strncpy(opts.transport, argv[++idx], sizeof(opts.transport) - 1);
                opts.transport_explicit = true;
            }
        } else if (strcmp(argv[idx], "--max-queries") == 0) {
            if (idx + 1 < argc) {
                opts.max_queries = atoi(argv[++idx]);
            }
        } else if (strcmp(argv[idx], "+dnssec") == 0 || strcmp(argv[idx], "+do") == 0) {
            opts.dnssec = true;
        } else if (strcmp(argv[idx], "+nodnssec") == 0 || strcmp(argv[idx], "+nodo") == 0) {
            opts.dnssec = false;
        }
        idx++;
    }

    if (!opts.input_path[0] || !opts.server1_host[0]) {
        fprintf(stderr, "Usage: dag --replay <traffic_file> --server1 <host[:port]> [--server2 <host[:port]>] "
                        "[--compare-recorded] [--rate <qps>] [--workers <N>] [--diff] [--output <text|json>] "
                        "[--transport <udp|tcp|tls|doh>] [--max-queries <N>] [--ignore-ttl] "
                        "[--timeout-ms <N>] [--stop-after <N>] [--output-diff <file>] "
                        "[--server1-transport <transport>] [--server2-transport <transport>]\n");
        return 1;
    }

    if (opts.compare_recorded && opts.has_server2) {
        fprintf(stderr, "[ERROR] --compare-recorded and --server2 cannot be specified together. "
                        "Choose either comparing two live servers or comparing with recorded responses.\n");
        return 1;
    }

    if (opts.output_diff_path[0]) {
        if (strcmp(opts.output_diff_path, "-") == 0) {
            opts.diff_fp = stdout;
        } else {
            opts.diff_fp = fopen(opts.output_diff_path, "w");
            if (!opts.diff_fp) {
                fprintf(stderr, "[WARNING] Cannot open diff output file %s: %s\n",
                        opts.output_diff_path, strerror(errno));
            }
        }
    }

    FILE *fp = fopen(opts.input_path, "rb");
    if (!fp) {
        fprintf(stderr, "[ERROR] Cannot open replay input file: %s (%s)\n", opts.input_path, strerror(errno));
        if (opts.diff_fp && opts.diff_fp != stdout) fclose(opts.diff_fp);
        return 1;
    }

    replay_queue_t *queue = calloc(1, sizeof(replay_queue_t));
    if (!queue) {
        fprintf(stderr, "[ERROR] Failed to allocate replay queue\n");
        fclose(fp);
        if (opts.diff_fp && opts.diff_fp != stdout) fclose(opts.diff_fp);
        return 1;
    }
    pthread_mutex_init(&queue->lock, NULL);
    pthread_cond_init(&queue->not_empty, NULL);
    pthread_cond_init(&queue->not_full, NULL);

    worker_shared_t ws;
    memset(&ws, 0, sizeof(ws));
    ws.queue = queue;
    ws.opts = &opts;
    pthread_mutex_init(&ws.stats_lock, NULL);

    uint8_t *io_buf = malloc(65536);
    if (!io_buf) {
        fprintf(stderr, "[ERROR] Failed to allocate replay I/O buffer\n");
        pthread_mutex_destroy(&queue->lock);
        pthread_cond_destroy(&queue->not_empty);
        pthread_cond_destroy(&queue->not_full);
        pthread_mutex_destroy(&ws.stats_lock);
        free(queue);
        fclose(fp);
        if (opts.diff_fp && opts.diff_fp != stdout) fclose(opts.diff_fp);
        return 1;
    }

    pthread_t threads[64];
    for (int i = 0; i < opts.num_workers; i++) {
        pthread_create(&threads[i], NULL, replay_worker_func, &ws);
    }

    // Detect format from header
    uint8_t magic[4];
    size_t nread = fread(magic, 1, 4, fp);
    fseek(fp, 0, SEEK_SET);

    uint64_t seq = 0;
    uint32_t rate_delay_us = (opts.rate_qps > 0) ? (uint32_t)(1000000 / opts.rate_qps) : 0;

    if (nread == 4 && ((magic[0] == 0xa1 && magic[1] == 0xb2 && magic[2] == 0xc3 && magic[3] == 0xd4) ||
                       (magic[0] == 0xd4 && magic[1] == 0xc3 && magic[2] == 0xb2 && magic[3] == 0xa1))) {
        // PCAP File
        bool is_le = (magic[0] == 0xd4);
        uint8_t pcap_hdr[24];
        if (fread(pcap_hdr, 1, 24, fp) == 24) {
            uint32_t linktype = pcap_read_u32(pcap_hdr + 20, is_le);

            if (opts.compare_recorded) {
                dns_pair_table_t *pairs = calloc(1, sizeof(dns_pair_table_t));
                tcp_reasm_table_t *tcp_reasm = tcp_reasm_create(4096, 256 * 1024);
                uint64_t missing_response_count = 0;

                tcp_reasm_cb_ctx_t cbctx;
                memset(&cbctx, 0, sizeof(cbctx));
                cbctx.pairs = pairs;
                cbctx.queue = queue;
                cbctx.seq_ptr = &seq;
                cbctx.opts = &opts;
                cbctx.ws = &ws;

                uint8_t rec_hdr[16];
                while (fread(rec_hdr, 1, 16, fp) == 16) {
                    uint32_t incl_len = pcap_read_u32(rec_hdr + 8, is_le);
                    if (incl_len > 65536) break;
                    if (fread(io_buf, 1, incl_len, fp) != incl_len) break;

                    pcap_l4_info_t l4;
                    if (!pcap_extract_l4(io_buf, incl_len, linktype, &l4)) continue;

                    if (l4.l4_proto == 17 /* UDP */) {
                        if (l4.l4_payload_len >= 12) {
                            uint8_t addr_key[32];
                            uint16_t port_key[2];
                            int dir = 0;
                            pcap_canonicalize_endpoints(l4.src_addr, l4.src_port, l4.dst_addr, l4.dst_port,
                                                        addr_key, port_key, &dir);
                            if (!dns_pair_table_feed_wire(pairs, addr_key, port_key, 17 /* UDP */,
                                                         "udp", l4.l4_payload, l4.l4_payload_len,
                                                         queue, &seq, &opts, &ws)) {
                                break;
                            }
                        }
                    } else if (l4.l4_proto == 6 /* TCP */) {
                        tcp_reasm_feed(tcp_reasm, &l4, (tcp_reasm_message_cb)tcp_reasm_dns_cb, &cbctx);
                        if (opts.max_queries > 0 && (int)seq >= opts.max_queries) break;
                        if (opts.stop_after > 0) {
                            pthread_mutex_lock(&ws.stats_lock);
                            uint64_t diff_cnt = ws.diff_stats.total_compared - ws.diff_stats.identical;
                            pthread_mutex_unlock(&ws.stats_lock);
                            if (diff_cnt >= (uint64_t)opts.stop_after) {
                                pthread_mutex_lock(&queue->lock);
                                queue->count = 0;
                                queue->done = true;
                                pthread_cond_broadcast(&queue->not_empty);
                                pthread_mutex_unlock(&queue->lock);
                                break;
                            }
                        }
                    }
                }

                dns_pair_table_flush_incomplete(pairs, &missing_response_count);
                if (missing_response_count > 0) {
                    fprintf(stderr, "[WARNING] %lu query(ies) had no recorded response in capture "
                                    "(incomplete capture or timeout). Excluding from comparison.\n",
                            (unsigned long)missing_response_count);
                }
                tcp_reasm_destroy(tcp_reasm);
                free(pairs);
            } else {
                uint8_t rec_hdr[16];
                uint8_t dns_wire[MAX_REPLAY_PACKET_LEN];
                size_t dns_len = 0;

                while (fread(rec_hdr, 1, 16, fp) == 16) {
                    uint32_t incl_len = pcap_read_u32(rec_hdr + 8, is_le);
                    if (incl_len > 65536) break;
                    if (fread(io_buf, 1, incl_len, fp) != incl_len) break;

                    char pkt_transport[16] = "";
                    if (parse_pcap_packet_ex(io_buf, incl_len, linktype, dns_wire, &dns_len, pkt_transport, sizeof(pkt_transport))) {
                        seq++;
                        if (!enqueue_task(queue, dns_wire, dns_len, seq, pkt_transport)) {
                            break;
                        }
                        if (opts.max_queries > 0 && (int)seq >= opts.max_queries) break;
                        if (opts.stop_after > 0) {
                            pthread_mutex_lock(&ws.stats_lock);
                            uint64_t diff_cnt = ws.diff_stats.total_compared - ws.diff_stats.identical;
                            pthread_mutex_unlock(&ws.stats_lock);
                            if (diff_cnt >= (uint64_t)opts.stop_after) {
                                pthread_mutex_lock(&queue->lock);
                                queue->count = 0;
                                queue->done = true;
                                pthread_cond_broadcast(&queue->not_empty);
                                pthread_mutex_unlock(&queue->lock);
                                break;
                            }
                        }
                        if (rate_delay_us > 0) replay_sleep_us(rate_delay_us);
                    }
                }
            }
        }
    } else if (nread == 4 && (
               (magic[0] == 0 && magic[1] == 0 && magic[2] == 0 && magic[3] == 0) ||
               (strrchr(opts.input_path, '.') && (
                   strcasecmp(strrchr(opts.input_path, '.'), ".dnstap") == 0 ||
                   strcasecmp(strrchr(opts.input_path, '.'), ".fstrm") == 0)))) {
        // dnstap Frame Streams
        if (opts.compare_recorded) {
            dns_pair_table_t *pairs = calloc(1, sizeof(dns_pair_table_t));
            uint64_t missing_response_count = 0;
            uint8_t frame_hdr[8];

            while (fread(frame_hdr, 1, 4, fp) == 4) {
                uint32_t len = ((uint32_t)frame_hdr[0] << 24) | ((uint32_t)frame_hdr[1] << 16) |
                               ((uint32_t)frame_hdr[2] << 8) | frame_hdr[3];
                if (len == 0) { // Control frame
                    if (fread(frame_hdr + 4, 1, 4, fp) != 4) break;
                    uint32_t clen = ((uint32_t)frame_hdr[4] << 24) | ((uint32_t)frame_hdr[5] << 16) |
                                    ((uint32_t)frame_hdr[6] << 8) | frame_hdr[7];
                    if (clen > 65536) break;
                    if (fread(io_buf, 1, clen, fp) != clen) break;
                    continue;
                }
                if (len > 65536) break;
                if (fread(io_buf, 1, len, fp) != len) break;

                dnstap_frame_info_t dinfo;
                if (parse_dnstap_data_frame_full(io_buf, len, &dinfo)) {
                    if (dinfo.has_wire) {
                        uint8_t addr_key[32];
                        memset(addr_key, 0, sizeof(addr_key));
                        memcpy(addr_key, dinfo.client_addr, 16);
                        uint16_t port_key[2] = { dinfo.client_port, 0 };
                        const char *trans = (dinfo.protocol == 6) ? "tcp" : "udp";
                        if (!dns_pair_table_feed_wire(pairs, addr_key, port_key, dinfo.protocol,
                                                     trans, dinfo.wire, dinfo.wire_len,
                                                     queue, &seq, &opts, &ws)) {
                            break;
                        }
                    }
                }
            }

            dns_pair_table_flush_incomplete(pairs, &missing_response_count);
            if (missing_response_count > 0) {
                fprintf(stderr, "[WARNING] %lu query(ies) had no recorded response in capture "
                                "(incomplete capture or timeout). Excluding from comparison.\n",
                        (unsigned long)missing_response_count);
            }
            free(pairs);
        } else {
            uint8_t frame_hdr[8];
            uint8_t dns_wire[MAX_REPLAY_PACKET_LEN];
            size_t dns_len = 0;

            while (fread(frame_hdr, 1, 4, fp) == 4) {
                uint32_t len = ((uint32_t)frame_hdr[0] << 24) | ((uint32_t)frame_hdr[1] << 16) |
                               ((uint32_t)frame_hdr[2] << 8) | frame_hdr[3];
                if (len == 0) { // Control frame
                    if (fread(frame_hdr + 4, 1, 4, fp) != 4) break;
                    uint32_t clen = ((uint32_t)frame_hdr[4] << 24) | ((uint32_t)frame_hdr[5] << 16) |
                                    ((uint32_t)frame_hdr[6] << 8) | frame_hdr[7];
                    if (clen > 65536) break;
                    if (fread(io_buf, 1, clen, fp) != clen) break;
                    continue;
                }
                if (len > 65536) break;
                if (fread(io_buf, 1, len, fp) != len) break;

                char frame_transport[16] = "";
                if (parse_dnstap_data_frame_ex(io_buf, len, dns_wire, &dns_len, frame_transport, sizeof(frame_transport))) {
                    seq++;
                    if (!enqueue_task(queue, dns_wire, dns_len, seq, frame_transport)) {
                        break;
                    }
                    if (opts.max_queries > 0 && (int)seq >= opts.max_queries) break;
                    if (opts.stop_after > 0) {
                        pthread_mutex_lock(&ws.stats_lock);
                        uint64_t diff_cnt = ws.diff_stats.total_compared - ws.diff_stats.identical;
                        pthread_mutex_unlock(&ws.stats_lock);
                        if (diff_cnt >= (uint64_t)opts.stop_after) {
                            pthread_mutex_lock(&queue->lock);
                            queue->count = 0;
                            queue->done = true;
                            pthread_cond_broadcast(&queue->not_empty);
                            pthread_mutex_unlock(&queue->lock);
                            break;
                        }
                    }
                    if (rate_delay_us > 0) replay_sleep_us(rate_delay_us);
                }
            }
        }
    } else {
        // Text queries: line by line "qname [qtype]"
        if (opts.compare_recorded) {
            fprintf(stderr, "[ERROR] --compare-recorded cannot be used with text query files "
                            "(no recorded responses available). Please provide a .pcap or .dnstap file.\n");
            fclose(fp);
            if (opts.diff_fp && opts.diff_fp != stdout) fclose(opts.diff_fp);
            pthread_mutex_lock(&queue->lock);
            queue->done = true;
            pthread_cond_broadcast(&queue->not_empty);
            pthread_mutex_unlock(&queue->lock);
            for (int i = 0; i < opts.num_workers; i++) {
                pthread_join(threads[i], NULL);
            }
            pthread_mutex_destroy(&queue->lock);
            pthread_cond_destroy(&queue->not_empty);
            pthread_cond_destroy(&queue->not_full);
            pthread_mutex_destroy(&ws.stats_lock);
            free(queue);
            free(io_buf);
            return 1;
        }

        char line[1024];
        uint8_t dns_wire[MAX_REPLAY_PACKET_LEN];
        while (fgets(line, sizeof(line), fp)) {
            char *p = line;
            while (*p && isspace((unsigned char)*p)) p++;
            if (!*p || *p == '#' || *p == ';') continue;
            char *nl = strchr(p, '\n');
            if (nl) *nl = '\0';

            char qname[256] = "";
            char qtype_str[64] = "A";
            int matched = sscanf(p, "%255s %63s", qname, qtype_str);
            if (matched >= 1) {
                uint16_t qtype = get_type_code(qtype_str);
                if (qtype == 0) qtype = 1;
                bool line_dnssec = opts.dnssec;
                if (strstr(p, "+dnssec") != NULL || strstr(p, "+do") != NULL) {
                    line_dnssec = true;
                } else if (strstr(p, "+nodnssec") != NULL || strstr(p, "+nodo") != NULL) {
                    line_dnssec = false;
                }
                char line_transport[16] = "";
                if (strstr(p, "+tcp") != NULL) {
                    strncpy(line_transport, "tcp", sizeof(line_transport) - 1);
                } else if (strstr(p, "+udp") != NULL) {
                    strncpy(line_transport, "udp", sizeof(line_transport) - 1);
                }
                size_t wlen = build_text_query(qname, qtype, line_dnssec, dns_wire, sizeof(dns_wire));
                if (wlen > 0) {
                    seq++;
                    if (!enqueue_task(queue, dns_wire, wlen, seq, line_transport)) {
                        break;
                    }
                    if (opts.max_queries > 0 && (int)seq >= opts.max_queries) break;
                    if (opts.stop_after > 0) {
                        pthread_mutex_lock(&ws.stats_lock);
                        uint64_t diff_cnt = ws.diff_stats.total_compared - ws.diff_stats.identical;
                        pthread_mutex_unlock(&ws.stats_lock);
                        if (diff_cnt >= (uint64_t)opts.stop_after) {
                            pthread_mutex_lock(&queue->lock);
                            queue->count = 0;
                            queue->done = true;
                            pthread_cond_broadcast(&queue->not_empty);
                            pthread_mutex_unlock(&queue->lock);
                            break;
                        }
                    }
                    if (rate_delay_us > 0) replay_sleep_us(rate_delay_us);
                }
            }
        }
    }
    fclose(fp);

    // Notify workers of completion
    pthread_mutex_lock(&queue->lock);
    queue->done = true;
    pthread_cond_broadcast(&queue->not_empty);
    pthread_mutex_unlock(&queue->lock);

    for (int i = 0; i < opts.num_workers; i++) {
        pthread_join(threads[i], NULL);
    }

    double avg_rtt1 = (ws.s1_stats.responses_received > 0) ?
                      (ws.s1_stats.total_rtt_ms / ws.s1_stats.responses_received) : 0.0;
    double avg_rtt2 = (ws.s2_stats.responses_received > 0) ?
                      (ws.s2_stats.total_rtt_ms / ws.s2_stats.responses_received) : 0.0;

    unsigned long total_queries_count = (unsigned long)seq;
    if (opts.stop_after > 0 && (opts.has_server2 || opts.compare_recorded)) {
        total_queries_count = (unsigned long)ws.diff_stats.total_compared;
    }

    const char *s2_label_text = opts.compare_recorded ? "Recorded (from capture)" : "Server 2";
    const char *s2_label_json = opts.compare_recorded ? "recorded" : "server2";

    if (opts.output_json) {
        printf("{\n");
        printf("  \"total_queries\": %lu,\n", total_queries_count);
        printf("  \"server1\": {\n");
        printf("    \"target\": \"%s:%d\",\n", opts.server1_host, opts.server1_port);
        printf("    \"sent\": %lu,\n", (unsigned long)ws.s1_stats.queries_sent);
        printf("    \"received\": %lu,\n", (unsigned long)ws.s1_stats.responses_received);
        printf("    \"timeouts\": %lu,\n", (unsigned long)ws.s1_stats.timeouts);
        printf("    \"avg_rtt_ms\": %.2f,\n", avg_rtt1);
        printf("    \"noerror\": %lu,\n", (unsigned long)ws.s1_stats.rcode_counts[0]);
        printf("    \"nxdomain\": %lu,\n", (unsigned long)ws.s1_stats.rcode_counts[3]);
        printf("    \"servfail\": %lu\n", (unsigned long)ws.s1_stats.rcode_counts[2]);
        printf("  }");
        if (opts.has_server2 || opts.compare_recorded) {
            printf(",\n  \"%s\": {\n", s2_label_json);
            if (opts.compare_recorded) {
                printf("    \"source\": \"%s\",\n", opts.input_path);
            } else {
                printf("    \"target\": \"%s:%d\",\n", opts.server2_host, opts.server2_port);
            }
            printf("    \"sent\": %lu,\n", (unsigned long)ws.s2_stats.queries_sent);
            printf("    \"received\": %lu,\n", (unsigned long)ws.s2_stats.responses_received);
            printf("    \"timeouts\": %lu,\n", (unsigned long)ws.s2_stats.timeouts);
            printf("    \"avg_rtt_ms\": %.2f,\n", avg_rtt2);
            printf("    \"noerror\": %lu,\n", (unsigned long)ws.s2_stats.rcode_counts[0]);
            printf("    \"nxdomain\": %lu,\n", (unsigned long)ws.s2_stats.rcode_counts[3]);
            printf("    \"servfail\": %lu\n", (unsigned long)ws.s2_stats.rcode_counts[2]);
            printf("  },\n");
            printf("  \"diff\": {\n");
            printf("    \"compared\": %lu,\n", (unsigned long)ws.diff_stats.total_compared);
            printf("    \"identical\": %lu,\n", (unsigned long)ws.diff_stats.identical);
            printf("    \"identical_queries\": %lu,\n", (unsigned long)ws.diff_stats.identical);
            printf("    \"mismatched_queries\": %lu,\n", (unsigned long)(ws.diff_stats.total_compared - ws.diff_stats.identical));
            printf("    \"rcode_mismatches\": %lu,\n", (unsigned long)ws.diff_stats.rcode_mismatches);
            printf("    \"flags_mismatches\": %lu,\n", (unsigned long)ws.diff_stats.flags_mismatches);
            printf("    \"ancount_mismatches\": %lu,\n", (unsigned long)ws.diff_stats.ancount_mismatches);
            printf("    \"rrset_mismatches\": %lu,\n", (unsigned long)ws.diff_stats.rrset_mismatches);
            printf("    \"glue_missing_diffs\": %lu,\n", (unsigned long)ws.diff_stats.glue_missing_diffs);
            printf("    \"edns_diffs\": %lu,\n", (unsigned long)ws.diff_stats.edns_diffs);
            printf("    \"dnssec_rrsig_diffs\": %lu,\n", (unsigned long)ws.diff_stats.dnssec_rrsig_diffs);
            printf("    \"dnssec_nsec_diffs\": %lu,\n", (unsigned long)ws.diff_stats.dnssec_nsec_diffs);
            printf("    \"cname_chain_diffs\": %lu\n", (unsigned long)ws.diff_stats.cname_chain_diffs);
            printf("  }\n");
        } else {
            printf("\n");
        }
        printf("}\n");
    } else {
        printf("\n================ DNS Replay Summary ================\n");
        printf("Total Queries Replayed: %lu\n", total_queries_count);
        printf("Transport:              %s\n", opts.transport);
        printf("Workers:                %d\n", opts.num_workers);
        printf("\n--- Server 1 (%s:%d) ---\n", opts.server1_host, opts.server1_port);
        printf("  Server 1: %lu responses\n", (unsigned long)ws.s1_stats.responses_received);
        printf("  Sent:     %lu\n", (unsigned long)ws.s1_stats.queries_sent);
        printf("  Received: %lu\n", (unsigned long)ws.s1_stats.responses_received);
        printf("  Timeouts: %lu\n", (unsigned long)ws.s1_stats.timeouts);
        printf("  Avg RTT:  %.2f ms\n", avg_rtt1);
        printf("  RCODEs:   NOERROR=%lu NXDOMAIN=%lu SERVFAIL=%lu REFUSED=%lu\n",
               (unsigned long)ws.s1_stats.rcode_counts[0], (unsigned long)ws.s1_stats.rcode_counts[3],
               (unsigned long)ws.s1_stats.rcode_counts[2], (unsigned long)ws.s1_stats.rcode_counts[5]);

        if (opts.has_server2 || opts.compare_recorded) {
            if (opts.compare_recorded) {
                printf("\n--- %s ---\n", s2_label_text);
                printf("  Source:   %s\n", opts.input_path);
            } else {
                printf("\n--- %s (%s:%d) ---\n", s2_label_text, opts.server2_host, opts.server2_port);
            }
            printf("  Responses: %lu\n", (unsigned long)ws.s2_stats.responses_received);
            printf("  Sent/Pairs: %lu\n", (unsigned long)ws.s2_stats.queries_sent);
            printf("  Received:  %lu\n", (unsigned long)ws.s2_stats.responses_received);
            printf("  Timeouts:  %lu\n", (unsigned long)ws.s2_stats.timeouts);
            if (!opts.compare_recorded) {
                printf("  Avg RTT:   %.2f ms\n", avg_rtt2);
            }
            printf("  RCODEs:    NOERROR=%lu NXDOMAIN=%lu SERVFAIL=%lu REFUSED=%lu\n",
                   (unsigned long)ws.s2_stats.rcode_counts[0], (unsigned long)ws.s2_stats.rcode_counts[3],
                   (unsigned long)ws.s2_stats.rcode_counts[2], (unsigned long)ws.s2_stats.rcode_counts[5]);

            printf("\n--- Differential Comparison ---\n");
            printf("  Compared:           %lu\n", (unsigned long)ws.diff_stats.total_compared);
            printf("  Identical responses: %lu (%.1f%%)\n", (unsigned long)ws.diff_stats.identical,
                   ws.diff_stats.total_compared > 0 ? (100.0 * ws.diff_stats.identical / ws.diff_stats.total_compared) : 0.0);
            printf("  Mismatched responses: %lu\n", (unsigned long)(ws.diff_stats.total_compared - ws.diff_stats.identical));
            printf("  RCODE Mismatches:   %lu\n", (unsigned long)ws.diff_stats.rcode_mismatches);
            printf("  Flags Mismatches:   %lu\n", (unsigned long)ws.diff_stats.flags_mismatches);
            printf("  ANCOUNT Mismatches: %lu\n", (unsigned long)ws.diff_stats.ancount_mismatches);
            printf("  RRset Mismatches:   %lu\n", (unsigned long)ws.diff_stats.rrset_mismatches);
            printf("  Glue Missing:       %lu\n", (unsigned long)ws.diff_stats.glue_missing_diffs);
            printf("  EDNS Diffs:         %lu\n", (unsigned long)ws.diff_stats.edns_diffs);
            printf("  DNSSEC RRSIG Diffs: %lu\n", (unsigned long)ws.diff_stats.dnssec_rrsig_diffs);
            printf("  DNSSEC NSEC Diffs:  %lu\n", (unsigned long)ws.diff_stats.dnssec_nsec_diffs);
            printf("  CNAME Chain Diffs:  %lu\n", (unsigned long)ws.diff_stats.cname_chain_diffs);
        }
        printf("====================================================\n");
    }

    if (opts.diff_fp && opts.diff_fp != stdout) {
        fclose(opts.diff_fp);
        opts.diff_fp = NULL;
    }

    pthread_mutex_destroy(&queue->lock);
    pthread_cond_destroy(&queue->not_empty);
    pthread_cond_destroy(&queue->not_full);
    pthread_mutex_destroy(&ws.stats_lock);
    free(queue);
    free(io_buf);

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}

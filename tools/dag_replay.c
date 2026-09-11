#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "dag_replay.h"


#define REPLAY_QUEUE_CAPACITY 1024
#define MAX_REPLAY_PACKET_LEN 4096

typedef struct {
    uint8_t pkt[MAX_REPLAY_PACKET_LEN];
    size_t pkt_len;
    uint64_t seq;
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
} diff_stats_t;

typedef struct {
    char input_path[512];
    char server1_host[128];
    int server1_port;
    char server2_host[128];
    int server2_port;
    bool has_server2;
    int rate_qps;
    int num_workers;
    bool do_diff;
    bool output_json;
    char transport[16];
    int max_queries;
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

bool parse_pcap_packet(const uint8_t *data, size_t len, uint32_t linktype, uint8_t *out_dns, size_t *out_dns_len) {
    if (!data || len < 14 || !out_dns || !out_dns_len) return false;

    size_t ip_offset = 0;
    if (linktype == 1) { // LINKTYPE_ETHERNET
        if (len < 14) return false;
        uint16_t ethertype = ((uint16_t)data[12] << 8) | data[13];
        ip_offset = 14;
        if (ethertype == 0x8100) { // 802.1Q VLAN
            if (len < 18) return false;
            ethertype = ((uint16_t)data[16] << 8) | data[17];
            ip_offset = 18;
        }
        if (ethertype != 0x0800 && ethertype != 0x86DD) {
            return false;
        }
    } else if (linktype == 113) { // LINKTYPE_LINUX_SLL
        if (len < 16) return false;
        uint16_t proto = ((uint16_t)data[14] << 8) | data[15];
        ip_offset = 16;
        if (proto != 0x0800 && proto != 0x86DD) return false;
    } else if (linktype == 12 || linktype == 101) { // RAW IP
        ip_offset = 0;
    } else {
        if ((data[0] >> 4) == 4 || (data[0] >> 4) == 6) {
            ip_offset = 0;
        } else if (len >= 14 && (((data[12] << 8) | data[13]) == 0x0800 || ((data[12] << 8) | data[13]) == 0x86DD)) {
            ip_offset = 14;
        } else {
            return false;
        }
    }

    if (ip_offset >= len) return false;
    uint8_t ip_version = data[ip_offset] >> 4;
    size_t l4_offset = 0;
    uint8_t l4_proto = 0;

    if (ip_version == 4) {
        if (ip_offset + 20 > len) return false;
        uint8_t ihl = (data[ip_offset] & 0x0F) * 4;
        if (ihl < 20 || ip_offset + ihl > len) return false;
        l4_proto = data[ip_offset + 9];
        l4_offset = ip_offset + ihl;
    } else if (ip_version == 6) {
        if (ip_offset + 40 > len) return false;
        l4_proto = data[ip_offset + 6];
        l4_offset = ip_offset + 40;
    } else {
        return false;
    }

    size_t dns_offset = 0;
    size_t dns_len = 0;

    if (l4_proto == 17) { // UDP
        if (l4_offset + 8 > len) return false;
        uint16_t udp_len = ((uint16_t)data[l4_offset + 4] << 8) | data[l4_offset + 5];
        if (udp_len < 8 || l4_offset + udp_len > len) {
            dns_len = len - l4_offset - 8;
        } else {
            dns_len = udp_len - 8;
        }
        dns_offset = l4_offset + 8;
    } else if (l4_proto == 6) { // TCP
        if (l4_offset + 20 > len) return false;
        uint8_t tcp_hdr_len = ((data[l4_offset + 12] >> 4) & 0x0F) * 4;
        if (tcp_hdr_len < 20 || l4_offset + tcp_hdr_len > len) return false;
        dns_offset = l4_offset + tcp_hdr_len;
        if (dns_offset + 2 > len) return false;
        uint16_t tcp_dns_len = ((uint16_t)data[dns_offset] << 8) | data[dns_offset + 1];
        dns_offset += 2;
        dns_len = (dns_offset + tcp_dns_len <= len) ? tcp_dns_len : (len - dns_offset);
    } else {
        return false;
    }

    if (dns_len < 12 || dns_len > MAX_REPLAY_PACKET_LEN) return false;

    // Check QR bit: query must have QR=0
    if ((data[dns_offset + 2] & 0x80) != 0) return false;

    // Must have at least 1 question
    uint16_t qdcount = ((uint16_t)data[dns_offset + 4] << 8) | data[dns_offset + 5];
    if (qdcount == 0) return false;

    memcpy(out_dns, data + dns_offset, dns_len);
    *out_dns_len = dns_len;
    return true;
}

bool parse_dnstap_data_frame(const uint8_t *data, size_t len, uint8_t *out_dns, size_t *out_dns_len) {
    if (!data || len == 0 || !out_dns || !out_dns_len) return false;
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
            if (field_num == 14) { // message
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
        } else if (wire_type == 2) {
            uint64_t field_len = 0;
            size_t c = pb_decode_varint(msg_data + off, msg_len - off, &field_len);
            if (c == 0) break;
            off += c;
            if (off + field_len > msg_len) break;
            if (field_num == 10) { // query_message
                query_msg = msg_data + off;
                query_len = (size_t)field_len;
                break;
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
    memcpy(out_dns, query_msg, query_len);
    *out_dns_len = query_len;
    return true;
}

static size_t skip_dns_name(const uint8_t *pkt, size_t pkt_len, size_t off) {
    size_t cur = off;
    int jumps = 0;
    while (cur < pkt_len) {
        uint8_t len = pkt[cur];
        if (len == 0) {
            return (jumps == 0) ? (cur + 1) : off;
        }
        if ((len & 0xC0) == 0xC0) {
            if (cur + 1 >= pkt_len) return 0;
            return cur + 2;
        }
        cur += 1 + len;
    }
    return 0;
}

void diff_dns_responses(const uint8_t *resp1, size_t len1, const uint8_t *resp2, size_t len2, diff_result_t *out_diff) {
    memset(out_diff, 0, sizeof(*out_diff));
    out_diff->match = true;
    out_diff->rcode_match = true;
    out_diff->flags_match = true;
    out_diff->ancount_match = true;
    out_diff->rrset_match = true;

    if (!resp1 && !resp2 && len1 < 12 && len2 < 12) return;
    if (!resp1 || !resp2 || len1 < 12 || len2 < 12) {
        out_diff->match = false;
        snprintf(out_diff->diff_desc, sizeof(out_diff->diff_desc), "Length mismatch (truncated < 12 bytes or NULL)");
        return;
    }

    uint8_t rcode1 = resp1[3] & 0x0F;
    uint8_t rcode2 = resp2[3] & 0x0F;
    if (rcode1 != rcode2) {
        out_diff->match = false;
        out_diff->rcode_match = false;
        snprintf(out_diff->diff_desc, sizeof(out_diff->diff_desc), "RCODE mismatch: S1=%u S2=%u", rcode1, rcode2);
        return;
    }

    uint8_t flags1 = resp1[2] & 0x06; // AA (0x04) | TC (0x02)
    uint8_t flags2 = resp2[2] & 0x06;
    if (flags1 != flags2) {
        out_diff->match = false;
        out_diff->flags_match = false;
        snprintf(out_diff->diff_desc, sizeof(out_diff->diff_desc), "Flags mismatch: AA/TC S1=0x%02x S2=0x%02x", flags1, flags2);
        return;
    }

    uint16_t ancount1 = ((uint16_t)resp1[6] << 8) | resp1[7];
    uint16_t ancount2 = ((uint16_t)resp2[6] << 8) | resp2[7];
    if (ancount1 != ancount2) {
        out_diff->match = false;
        out_diff->ancount_match = false;
        snprintf(out_diff->diff_desc, sizeof(out_diff->diff_desc), "ANCOUNT mismatch: S1=%u S2=%u", ancount1, ancount2);
        return;
    }

    if (len1 == len2 && memcmp(resp1, resp2, len1) == 0) {
        return; // Exact wire match
    }

    // Skip question section on both
    uint16_t qd1 = ((uint16_t)resp1[4] << 8) | resp1[5];
    uint16_t qd2 = ((uint16_t)resp2[4] << 8) | resp2[5];
    size_t off1 = 12;
    for (uint16_t i = 0; i < qd1 && off1 < len1; i++) {
        off1 = skip_dns_name(resp1, len1, off1);
        if (off1 == 0 || off1 + 4 > len1) break;
        off1 += 4;
    }
    size_t off2 = 12;
    for (uint16_t i = 0; i < qd2 && off2 < len2; i++) {
        off2 = skip_dns_name(resp2, len2, off2);
        if (off2 == 0 || off2 + 4 > len2) break;
        off2 += 4;
    }

    if (ancount1 > 0 && off1 > 0 && off2 > 0) {
        // Compare types and RDATA in answer section
        for (uint16_t i = 0; i < ancount1; i++) {
            off1 = skip_dns_name(resp1, len1, off1);
            off2 = skip_dns_name(resp2, len2, off2);
            if (off1 == 0 || off1 + 10 > len1 || off2 == 0 || off2 + 10 > len2) {
                out_diff->match = false;
                out_diff->rrset_match = false;
                snprintf(out_diff->diff_desc, sizeof(out_diff->diff_desc), "Malformed RR header in answer");
                return;
            }
            uint16_t t1 = ((uint16_t)resp1[off1] << 8) | resp1[off1 + 1];
            uint16_t t2 = ((uint16_t)resp2[off2] << 8) | resp2[off2 + 1];
            uint16_t rdlen1 = ((uint16_t)resp1[off1 + 8] << 8) | resp1[off1 + 9];
            uint16_t rdlen2 = ((uint16_t)resp2[off2 + 8] << 8) | resp2[off2 + 9];
            if (t1 != t2) {
                out_diff->match = false;
                out_diff->rrset_match = false;
                snprintf(out_diff->diff_desc, sizeof(out_diff->diff_desc), "Answer type mismatch: S1=%u S2=%u", t1, t2);
                return;
            }
            size_t rdata1_off = off1 + 10;
            size_t rdata2_off = off2 + 10;
            if (rdata1_off + rdlen1 > len1 || rdata2_off + rdlen2 > len2) {
                out_diff->match = false;
                out_diff->rrset_match = false;
                snprintf(out_diff->diff_desc, sizeof(out_diff->diff_desc), "Malformed RDATA length in answer");
                return;
            }
            if (rdlen1 != rdlen2 || memcmp(resp1 + rdata1_off, resp2 + rdata2_off, rdlen1) != 0) {
                out_diff->match = false;
                out_diff->rrset_match = false;
                snprintf(out_diff->diff_desc, sizeof(out_diff->diff_desc), "Answer RDATA mismatch: S1 len=%u S2 len=%u", rdlen1, rdlen2);
                return;
            }
            off1 = rdata1_off + rdlen1;
            off2 = rdata2_off + rdlen2;
        }
    }

    uint16_t ns1 = ((uint16_t)resp1[8] << 8) | resp1[9];
    uint16_t ns2 = ((uint16_t)resp2[8] << 8) | resp2[9];
    if (ns1 != ns2) {
        out_diff->match = false;
        out_diff->rrset_match = false;
        snprintf(out_diff->diff_desc, sizeof(out_diff->diff_desc), "NSCOUNT mismatch: S1=%u S2=%u", ns1, ns2);
        return;
    }

    uint16_t ar1 = ((uint16_t)resp1[10] << 8) | resp1[11];
    uint16_t ar2 = ((uint16_t)resp2[10] << 8) | resp2[11];
    if (ar1 != ar2) {
        out_diff->match = false;
        out_diff->rrset_match = false;
        snprintf(out_diff->diff_desc, sizeof(out_diff->diff_desc), "ARCOUNT mismatch: S1=%u S2=%u", ar1, ar2);
        return;
    }

    if (len1 != len2 || (len1 >= 2 && memcmp(resp1 + 2, resp2 + 2, len1 - 2) != 0)) {
        out_diff->match = false;
        out_diff->rrset_match = false;
        snprintf(out_diff->diff_desc, sizeof(out_diff->diff_desc), "Payload wire mismatch");
        return;
    }
}

static ssize_t replay_exchange_posix(const char *server, int port, bool use_tcp,
                                     const uint8_t *pkt, size_t pkt_len,
                                     uint8_t *resp, size_t resp_cap, int timeout_sec) {
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
        struct timeval tv = { .tv_sec = timeout_sec > 0 ? timeout_sec : 2, .tv_usec = 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

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
        struct timeval tv = { .tv_sec = timeout_sec > 0 ? timeout_sec : 3, .tv_usec = 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

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
        ssize_t n = recv(fd, rlen_buf, 2, MSG_WAITALL);
        if (n != 2) {
            close(fd);
            return -1;
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
                               uint8_t *resp, size_t resp_cap, int timeout_sec) {
    bool use_tcp = (strcasecmp(transport, "tcp") == 0);
    return replay_exchange_posix(server, port, use_tcp, pkt, pkt_len, resp, resp_cap, timeout_sec);
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
        task = q->tasks[q->head];
        q->head = (q->head + 1) % REPLAY_QUEUE_CAPACITY;
        q->count--;
        pthread_cond_signal(&q->not_full);
        pthread_mutex_unlock(&q->lock);

        // Server 1 query
        uint8_t resp1[4096];
        struct timespec ts1_start, ts1_end;
        clock_gettime(CLOCK_MONOTONIC, &ts1_start);
        ssize_t r1 = replay_exchange(opts->server1_host, opts->server1_port, opts->transport,
                                     task.pkt, task.pkt_len, resp1, sizeof(resp1), 2);
        clock_gettime(CLOCK_MONOTONIC, &ts1_end);
        double rtt1_ms = (ts1_end.tv_sec - ts1_start.tv_sec) * 1000.0 +
                         (ts1_end.tv_nsec - ts1_start.tv_nsec) / 1000000.0;

        uint8_t resp2[4096];
        ssize_t r2 = -1;
        double rtt2_ms = 0.0;
        if (opts->has_server2) {
            struct timespec ts2_start, ts2_end;
            clock_gettime(CLOCK_MONOTONIC, &ts2_start);
            r2 = replay_exchange(opts->server2_host, opts->server2_port, opts->transport,
                                 task.pkt, task.pkt_len, resp2, sizeof(resp2), 2);
            clock_gettime(CLOCK_MONOTONIC, &ts2_end);
            rtt2_ms = (ts2_end.tv_sec - ts2_start.tv_sec) * 1000.0 +
                      (ts2_end.tv_nsec - ts2_start.tv_nsec) / 1000000.0;
        }

        diff_result_t diff;
        memset(&diff, 0, sizeof(diff));
        if (opts->has_server2) {
            if (r1 > 0 && r2 > 0) {
                diff_dns_responses(resp1, (size_t)r1, resp2, (size_t)r2, &diff);
            } else if (r1 <= 0 && r2 <= 0) {
                diff.match = true;
            } else {
                diff.match = false;
                snprintf(diff.diff_desc, sizeof(diff.diff_desc), "Reachability mismatch: S1=%s S2=%s",
                         r1 > 0 ? "OK" : "TIMEOUT", r2 > 0 ? "OK" : "TIMEOUT");
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

        if (opts->has_server2) {
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
                if (!diff.rcode_match) ws->diff_stats.rcode_mismatches++;
                if (!diff.flags_match) ws->diff_stats.flags_mismatches++;
                if (!diff.ancount_match) ws->diff_stats.ancount_mismatches++;
                if (!diff.rrset_match) ws->diff_stats.rrset_mismatches++;
                if (!opts->output_json && ws->diff_stats.total_compared <= 10) {
                    fprintf(stderr, "[DIFF #%lu] %s\n", (unsigned long)task.seq, diff.diff_desc);
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

static bool enqueue_task(replay_queue_t *q, const uint8_t *pkt, size_t len, uint64_t seq) {
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
    q->tail = (q->tail + 1) % REPLAY_QUEUE_CAPACITY;
    q->count++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
    return true;
}

static size_t build_text_query(const char *qname, uint16_t qtype, uint8_t *buf, size_t cap) {
    if (cap < 64) return 0;
    memset(buf, 0, 12);
    buf[0] = (uint8_t)(arc4random() & 0xFF);
    buf[1] = (uint8_t)(arc4random() & 0xFF);
    buf[2] = 0x01; // RD = 1
    buf[5] = 1;    // QDCOUNT = 1

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
        } else if (strcmp(argv[idx], "--rate") == 0) {
            if (idx + 1 < argc) {
                opts.rate_qps = atoi(argv[++idx]);
            }
        } else if (strcmp(argv[idx], "--workers") == 0) {
            if (idx + 1 < argc) {
                opts.num_workers = atoi(argv[++idx]);
                if (opts.num_workers < 1) opts.num_workers = 1;
                if (opts.num_workers > 64) opts.num_workers = 64;
            }
        } else if (strcmp(argv[idx], "--diff") == 0) {
            opts.do_diff = true;
        } else if (strcmp(argv[idx], "--output") == 0) {
            if (idx + 1 < argc) {
                idx++;
                if (strcasecmp(argv[idx], "json") == 0) opts.output_json = true;
            }
        } else if (strcmp(argv[idx], "--transport") == 0) {
            if (idx + 1 < argc) {
                strncpy(opts.transport, argv[++idx], sizeof(opts.transport) - 1);
            }
        } else if (strcmp(argv[idx], "--max-queries") == 0) {
            if (idx + 1 < argc) {
                opts.max_queries = atoi(argv[++idx]);
            }
        }
        idx++;
    }

    if (!opts.input_path[0] || !opts.server1_host[0]) {
        fprintf(stderr, "Usage: dag --replay <traffic_file> --server1 <host[:port]> [--server2 <host[:port]>] "
                        "[--rate <qps>] [--workers <N>] [--diff] [--output <text|json>] "
                        "[--transport <udp|tcp|tls|doh>] [--max-queries <N>]\n");
        return 1;
    }

    FILE *fp = fopen(opts.input_path, "rb");
    if (!fp) {
        fprintf(stderr, "[ERROR] Cannot open replay input file: %s (%s)\n", opts.input_path, strerror(errno));
        return 1;
    }

    replay_queue_t *queue = calloc(1, sizeof(replay_queue_t));
    if (!queue) {
        fprintf(stderr, "[ERROR] Failed to allocate replay queue\n");
        fclose(fp);
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
    useconds_t rate_delay_us = (opts.rate_qps > 0) ? (1000000 / opts.rate_qps) : 0;

    if (nread == 4 && ((magic[0] == 0xa1 && magic[1] == 0xb2 && magic[2] == 0xc3 && magic[3] == 0xd4) ||
                       (magic[0] == 0xd4 && magic[1] == 0xc3 && magic[2] == 0xb2 && magic[3] == 0xa1))) {
        // PCAP File
        bool swapped = (magic[0] == 0xd4);
        uint8_t pcap_hdr[24];
        if (fread(pcap_hdr, 1, 24, fp) == 24) {
            uint32_t linktype = swapped ?
                (((uint32_t)pcap_hdr[23] << 24) | ((uint32_t)pcap_hdr[22] << 16) | ((uint32_t)pcap_hdr[21] << 8) | pcap_hdr[20]) :
                (((uint32_t)pcap_hdr[20]) | ((uint32_t)pcap_hdr[21] << 8) | ((uint32_t)pcap_hdr[22] << 16) | ((uint32_t)pcap_hdr[23] << 24));

            uint8_t rec_hdr[16];
            uint8_t dns_wire[MAX_REPLAY_PACKET_LEN];
            size_t dns_len = 0;

            while (fread(rec_hdr, 1, 16, fp) == 16) {
                uint32_t incl_len = swapped ?
                    (((uint32_t)rec_hdr[11] << 24) | ((uint32_t)rec_hdr[10] << 16) | ((uint32_t)rec_hdr[9] << 8) | rec_hdr[8]) :
                    (((uint32_t)rec_hdr[8]) | ((uint32_t)rec_hdr[9] << 8) | ((uint32_t)rec_hdr[10] << 16) | ((uint32_t)rec_hdr[11] << 24));
                if (incl_len > 65536) break;
                if (fread(io_buf, 1, incl_len, fp) != incl_len) break;

                if (parse_pcap_packet(io_buf, incl_len, linktype, dns_wire, &dns_len)) {
                    seq++;
                    enqueue_task(queue, dns_wire, dns_len, seq);
                    if (opts.max_queries > 0 && (int)seq >= opts.max_queries) break;
                    if (rate_delay_us > 0) usleep(rate_delay_us);
                }
            }
        }
    } else if (nread == 4 && magic[0] == 0 && magic[1] == 0 && magic[2] == 0 && magic[3] == 0) {
        // dnstap Frame Streams
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

            if (parse_dnstap_data_frame(io_buf, len, dns_wire, &dns_len)) {
                seq++;
                enqueue_task(queue, dns_wire, dns_len, seq);
                if (opts.max_queries > 0 && (int)seq >= opts.max_queries) break;
                if (rate_delay_us > 0) usleep(rate_delay_us);
            }
        }
    } else {
        // Text queries: line by line "qname [qtype]"
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
                size_t wlen = build_text_query(qname, qtype, dns_wire, sizeof(dns_wire));
                if (wlen > 0) {
                    seq++;
                    enqueue_task(queue, dns_wire, wlen, seq);
                    if (opts.max_queries > 0 && (int)seq >= opts.max_queries) break;
                    if (rate_delay_us > 0) usleep(rate_delay_us);
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

    if (opts.output_json) {
        printf("{\n");
        printf("  \"total_queries\": %lu,\n", (unsigned long)seq);
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
        if (opts.has_server2) {
            printf(",\n  \"server2\": {\n");
            printf("    \"target\": \"%s:%d\",\n", opts.server2_host, opts.server2_port);
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
            printf("    \"rrset_mismatches\": %lu\n", (unsigned long)ws.diff_stats.rrset_mismatches);
            printf("  }\n");
        } else {
            printf("\n");
        }
        printf("}\n");
    } else {
        printf("\n================ DNS Replay Summary ================\n");
        printf("Total Queries Replayed: %lu\n", (unsigned long)seq);
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

        if (opts.has_server2) {
            printf("\n--- Server 2 (%s:%d) ---\n", opts.server2_host, opts.server2_port);
            printf("  Server 2: %lu responses\n", (unsigned long)ws.s2_stats.responses_received);
            printf("  Sent:     %lu\n", (unsigned long)ws.s2_stats.queries_sent);
            printf("  Received: %lu\n", (unsigned long)ws.s2_stats.responses_received);
            printf("  Timeouts: %lu\n", (unsigned long)ws.s2_stats.timeouts);
            printf("  Avg RTT:  %.2f ms\n", avg_rtt2);
            printf("  RCODEs:   NOERROR=%lu NXDOMAIN=%lu SERVFAIL=%lu REFUSED=%lu\n",
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
        }
        printf("====================================================\n");
    }

    pthread_mutex_destroy(&queue->lock);
    pthread_cond_destroy(&queue->not_empty);
    pthread_cond_destroy(&queue->not_full);
    pthread_mutex_destroy(&ws.stats_lock);
    free(queue);
    free(io_buf);

    return 0;
}

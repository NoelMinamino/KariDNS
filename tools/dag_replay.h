#ifndef DAG_REPLAY_H
#define DAG_REPLAY_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#include "../dns_wire.h"
#include "../dns_utils.h"

#define DIFF_RCODE           (1U << 0)
#define DIFF_FLAGS           (1U << 1)
#define DIFF_ANCOUNT         (1U << 2)
#define DIFF_NSCOUNT         (1U << 3)
#define DIFF_ARCOUNT         (1U << 4)
#define DIFF_ANSWER_RRSET    (1U << 5)
#define DIFF_AUTH_RRSET      (1U << 6)
#define DIFF_ADD_RRSET       (1U << 7)
#define DIFF_GLUE_MISSING    (1U << 8)
#define DIFF_EDNS            (1U << 9)
#define DIFF_DNSSEC_RRSIG    (1U << 10)
#define DIFF_DNSSEC_NSEC     (1U << 11)
#define DIFF_CNAME_CHAIN     (1U << 12)

typedef struct {
    bool match;
    uint32_t diff_flags; // Bitmask of DIFF_*
    bool rcode_match;
    bool flags_match;
    bool ancount_match;
    bool rrset_match;
    bool glue_missing;
    bool edns_diff;
    bool dnssec_rrsig_diff;
    bool dnssec_nsec_diff;
    bool cname_chain_diff;
    char diff_desc[512];
} diff_result_t;

int run_replay_mode(int argc, char **argv);

typedef struct {
    uint8_t message_type;      // 1 = AUTH_QUERY, 2 = AUTH_RESPONSE
    uint8_t protocol;          // IPPROTO_UDP(17) / IPPROTO_TCP(6)
    uint8_t client_addr[16];
    uint16_t client_port;
    bool has_wire;
    uint8_t wire[4096];
    size_t wire_len;
} dnstap_frame_info_t;

bool parse_pcap_packet(const uint8_t *data, size_t len, uint32_t linktype, uint8_t *out_dns, size_t *out_dns_len);
bool parse_pcap_packet_ex(const uint8_t *data, size_t len, uint32_t linktype, uint8_t *out_dns, size_t *out_dns_len, char *out_transport, size_t out_transport_len);
bool parse_dnstap_data_frame(const uint8_t *data, size_t len, uint8_t *out_dns, size_t *out_dns_len);
bool parse_dnstap_data_frame_ex(const uint8_t *data, size_t len, uint8_t *out_dns, size_t *out_dns_len, char *out_transport, size_t out_transport_len);
bool parse_dnstap_data_frame_full(const uint8_t *data, size_t len, dnstap_frame_info_t *out);
void diff_dns_responses(const uint8_t *resp1, size_t len1, const uint8_t *resp2, size_t len2, bool ignore_ttl, diff_result_t *out_diff);

#endif /* DAG_REPLAY_H */

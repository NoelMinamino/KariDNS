#ifndef DAG_REPLAY_H
#define DAG_REPLAY_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#include "../dns_wire.h"
#include "../dns_utils.h"

typedef struct {
    bool match;
    bool rcode_match;
    bool flags_match;
    bool ancount_match;
    bool rrset_match;
    char diff_desc[256];
} diff_result_t;

int run_replay_mode(int argc, char **argv);

bool parse_pcap_packet(const uint8_t *data, size_t len, uint32_t linktype, uint8_t *out_dns, size_t *out_dns_len);
bool parse_dnstap_data_frame(const uint8_t *data, size_t len, uint8_t *out_dns, size_t *out_dns_len);
void diff_dns_responses(const uint8_t *resp1, size_t len1, const uint8_t *resp2, size_t len2, diff_result_t *out_diff);

#endif /* DAG_REPLAY_H */

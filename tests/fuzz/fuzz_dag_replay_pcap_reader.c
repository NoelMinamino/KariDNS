#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "../../tools/dag_replay.h"

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 65536) return 0;

    uint8_t dns_buf[4096];
    size_t dns_len = sizeof(dns_buf);

    // Test PCAP frame parsing across standard linktypes
    static const uint32_t linktypes[] = {
        1,   // LINKTYPE_ETHERNET
        113, // LINKTYPE_LINUX_SLL
        12,  // LINKTYPE_RAW
        101, // LINKTYPE_RAW_ALT
        0,   // LINKTYPE_NULL
        65535 // Unknown / invalid linktype
    };

    char transport[16];
    for (size_t i = 0; i < sizeof(linktypes) / sizeof(linktypes[0]); i++) {
        dns_len = sizeof(dns_buf);
        (void)parse_pcap_packet(data, size, linktypes[i], dns_buf, &dns_len);
        dns_len = sizeof(dns_buf);
        (void)parse_pcap_packet_ex(data, size, linktypes[i], dns_buf, &dns_len, transport, sizeof(transport));
    }

    // Test dnstap protobuf data frame parsing
    dns_len = sizeof(dns_buf);
    (void)parse_dnstap_data_frame(data, size, dns_buf, &dns_len);
    dns_len = sizeof(dns_buf);
    (void)parse_dnstap_data_frame_ex(data, size, dns_buf, &dns_len, transport, sizeof(transport));

    // Dynamic linktype selection using first 4 bytes if available
    if (size >= 4) {
        uint32_t dynamic_linktype = ((uint32_t)data[0]) |
                                   ((uint32_t)data[1] << 8) |
                                   ((uint32_t)data[2] << 16) |
                                   ((uint32_t)data[3] << 24);
        dns_len = sizeof(dns_buf);
        (void)parse_pcap_packet(data + 4, size - 4, dynamic_linktype, dns_buf, &dns_len);
        dns_len = sizeof(dns_buf);
        (void)parse_pcap_packet_ex(data + 4, size - 4, dynamic_linktype, dns_buf, &dns_len, transport, sizeof(transport));
    }

    return 0;
}

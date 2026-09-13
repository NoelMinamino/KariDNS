#include <string.h>
#include "dag_pcap_l4.h"

bool pcap_extract_l4(const uint8_t *data, size_t len, uint32_t linktype, pcap_l4_info_t *out) {
    if (!data || len < 14 || !out) return false;
    memset(out, 0, sizeof(*out));

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
        out->ip_version = 4;
        memcpy(out->src_addr, data + ip_offset + 12, 4);
        memcpy(out->dst_addr, data + ip_offset + 16, 4);
        l4_offset = ip_offset + ihl;
    } else if (ip_version == 6) {
        if (ip_offset + 40 > len) return false;
        l4_proto = data[ip_offset + 6];
        out->ip_version = 6;
        memcpy(out->src_addr, data + ip_offset + 8, 16);
        memcpy(out->dst_addr, data + ip_offset + 24, 16);
        l4_offset = ip_offset + 40;
    } else {
        return false;
    }

    out->l4_proto = l4_proto;

    if (l4_proto == 17) { // UDP
        if (l4_offset + 8 > len) return false;
        out->src_port = ((uint16_t)data[l4_offset] << 8) | data[l4_offset + 1];
        out->dst_port = ((uint16_t)data[l4_offset + 2] << 8) | data[l4_offset + 3];
        uint16_t udp_len = ((uint16_t)data[l4_offset + 4] << 8) | data[l4_offset + 5];
        size_t payload_len = 0;
        if (udp_len < 8 || l4_offset + udp_len > len) {
            payload_len = len - l4_offset - 8;
        } else {
            payload_len = udp_len - 8;
        }
        out->l4_payload = data + l4_offset + 8;
        out->l4_payload_len = payload_len;
    } else if (l4_proto == 6) { // TCP
        if (l4_offset + 20 > len) return false;
        out->src_port = ((uint16_t)data[l4_offset] << 8) | data[l4_offset + 1];
        out->dst_port = ((uint16_t)data[l4_offset + 2] << 8) | data[l4_offset + 3];
        out->tcp_seq = ((uint32_t)data[l4_offset + 4] << 24) |
                       ((uint32_t)data[l4_offset + 5] << 16) |
                       ((uint32_t)data[l4_offset + 6] << 8)  |
                        (uint32_t)data[l4_offset + 7];
        out->tcp_ack = ((uint32_t)data[l4_offset + 8] << 24) |
                       ((uint32_t)data[l4_offset + 9] << 16) |
                       ((uint32_t)data[l4_offset + 10] << 8) |
                        (uint32_t)data[l4_offset + 11];
        uint8_t tcp_hdr_len = ((data[l4_offset + 12] >> 4) & 0x0F) * 4;
        if (tcp_hdr_len < 20 || l4_offset + tcp_hdr_len > len) return false;
        out->tcp_flags = data[l4_offset + 13];
        out->l4_payload = data + l4_offset + tcp_hdr_len;
        out->l4_payload_len = len - (l4_offset + tcp_hdr_len);
    } else {
        return false;
    }

    return true;
}

void pcap_canonicalize_endpoints(const uint8_t *src_addr, uint16_t src_port,
                                 const uint8_t *dst_addr, uint16_t dst_port,
                                 uint8_t *addr_key, uint16_t *port_key,
                                 int *out_direction) {
    int cmp = memcmp(src_addr, dst_addr, 16);
    if (cmp == 0) {
        if (src_port <= dst_port) {
            cmp = -1;
        } else {
            cmp = 1;
        }
    }

    if (cmp <= 0) {
        memcpy(addr_key, src_addr, 16);
        memcpy(addr_key + 16, dst_addr, 16);
        port_key[0] = src_port;
        port_key[1] = dst_port;
        if (out_direction) *out_direction = 0;
    } else {
        memcpy(addr_key, dst_addr, 16);
        memcpy(addr_key + 16, src_addr, 16);
        port_key[0] = dst_port;
        port_key[1] = src_port;
        if (out_direction) *out_direction = 1;
    }
}

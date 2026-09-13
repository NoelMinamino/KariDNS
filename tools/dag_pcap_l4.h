#ifndef DAG_PCAP_L4_H
#define DAG_PCAP_L4_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct {
    uint8_t  ip_version;      // 4 or 6
    uint8_t  l4_proto;        // IPPROTO_UDP(17) or IPPROTO_TCP(6)
    uint8_t  src_addr[16];    // IPv4は先頭4byteのみ使用
    uint8_t  dst_addr[16];
    uint16_t src_port;
    uint16_t dst_port;
    // TCPの場合のみ有効
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint8_t  tcp_flags;       // SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04
    const uint8_t *l4_payload;
    size_t   l4_payload_len;
} pcap_l4_info_t;

// リンク層(Ethernet/VLAN/Linux SLL/RAW IP/自動判定)を剥がし、IP+UDP/TCPヘッダを解析する。
// data/len は1個のPCAPレコードの生バイト列(incl_len分)。
// 戻り値: 解析成功なら true。ARP等DNSと無関係なフレーム・不正な長さは false。
bool pcap_extract_l4(const uint8_t *data, size_t len, uint32_t linktype, pcap_l4_info_t *out);

// 2つのエンドポイント(src/dst)を辞書順で正規化し、addr_key(32B), port_key(2xuint16), out_direction(0または1)を出力する。
void pcap_canonicalize_endpoints(const uint8_t *src_addr, uint16_t src_port,
                                 const uint8_t *dst_addr, uint16_t dst_port,
                                 uint8_t *addr_key, uint16_t *port_key,
                                 int *out_direction);

#endif /* DAG_PCAP_L4_H */

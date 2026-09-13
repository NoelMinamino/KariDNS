#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "../../tools/dag_pcap_l4.h"
#include "../../tools/dag_tcp_reassembly.h"

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

static void test_reasm_cb(void *user_ctx, uint32_t stream_id, int direction,
                          const uint8_t *addr_key, const uint16_t *port_key,
                          const uint8_t *dns_msg, size_t dns_msg_len) {
    (void)user_ctx;
    (void)stream_id;
    (void)direction;
    (void)addr_key;
    (void)port_key;
    (void)dns_msg;
    (void)dns_msg_len;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4 || size > 65536) return 0;

    tcp_reasm_table_t *reasm = tcp_reasm_create(64, 32 * 1024);
    if (!reasm) return 0;

    size_t off = 0;
    while (off + 8 < size) {
        pcap_l4_info_t l4;
        memset(&l4, 0, sizeof(l4));
        l4.ip_version = 4;
        l4.l4_proto = 6; // TCP
        uint8_t stream_sel = data[off++];
        l4.src_addr[0] = 192; l4.src_addr[1] = 0; l4.src_addr[2] = 2; l4.src_addr[3] = (stream_sel % 4) + 1;
        l4.dst_addr[0] = 192; l4.dst_addr[1] = 0; l4.dst_addr[2] = 2; l4.dst_addr[3] = 100;
        l4.src_port = 10000 + (stream_sel % 8);
        l4.dst_port = 53;

        l4.tcp_seq = ((uint32_t)data[off] << 24) | ((uint32_t)data[off + 1] << 16) |
                     ((uint32_t)data[off + 2] << 8) | (uint32_t)data[off + 3];
        off += 4;

        uint16_t seg_len = ((uint16_t)data[off] << 8) | data[off + 1];
        off += 2;
        seg_len = seg_len % 2048;

        if (off + seg_len > size) {
            seg_len = (uint16_t)(size - off);
        }

        l4.l4_payload = data + off;
        l4.l4_payload_len = seg_len;
        off += seg_len;

        tcp_reasm_feed(reasm, &l4, test_reasm_cb, NULL);
    }

    tcp_reasm_destroy(reasm);
    return 0;
}

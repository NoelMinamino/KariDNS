/* libFuzzer harness: what dnsqps reads from the network: the answer parser, and the frame readers of the kernel-bypass paths (UDP over IPv4 and IPv6,
 * ARP reply, neighbor advertisement, the raw reflector).  Every input is a packet from an untrusted peer; the checks are the sanitizers. */
#include "../../tools/dnsqps.h"
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const uint8_t ip4[4] = { 192, 0, 2, 2 }, ip6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    static const uint8_t mac[6] = { 2, 0, 0, 0, 0, 1 };
    uint8_t out[2048], m[6];
    dq_resp_t r;
    dq_udp_view_t v;
    dq_resp_parse(data, size, &r);
    if (dq_frame_parse_udp(data, size, false, ip4, &v) == 0 && v.plen > 0) dq_resp_parse(v.payload, v.plen, &r);
    if (dq_frame_parse_udp(data, size, true, ip6, &v) == 0 && v.plen > 0) dq_resp_parse(v.payload, v.plen, &r);
    dq_arp_reply_parse(data, size, ip4, m);
    dq_nd_adv_parse(data, size, ip6, m);
    dq_frame_reflect(data, size, false, ip4, mac, 5300, out, sizeof out);
    dq_frame_reflect(data, size, true, ip6, mac, 5300, out, sizeof out);
    /* a pre-built frame from the input patched in place: any length, any cookie offset, either family */
    if (size > 3) {
        dq_fsend_t s;
        memset(&s, 0, sizeof s);
        s.frame = data + 3;
        s.flen = (uint16_t)(size - 3);
        s.id = (uint16_t)(data[0] << 8);
        s.cookie_off = (uint16_t)(data[1] & 0x7F);
        s.set_sip = (data[2] & 1) != 0;
        memcpy(s.cookie, data, 3);
        dq_frame_emit(out, sizeof out, &s, (data[2] & 2) != 0, 40000);
        dq_frame_parse_udp_pfx(data, size, false, ip4, mac, &v);
    }
    return 0;
}

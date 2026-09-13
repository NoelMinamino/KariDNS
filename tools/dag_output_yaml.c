#include "dag_output_yaml.h"

// YAML single-quoted scalar内で安全な形にエスケープする（'を''に置換するのみ）
void yaml_single_quote_escape(const char *src, char *dst, size_t dst_cap) {
    if (!dst || dst_cap == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t d = 0;
    for (size_t s = 0; src[s] != '\0' && d + 1 < dst_cap; s++) {
        if (src[s] == '\'') {
            if (d + 2 >= dst_cap) break;
            dst[d++] = '\'';
            dst[d++] = '\'';
        } else {
            dst[d++] = src[s];
        }
    }
    dst[d] = '\0';
}

// YAML double-quoted scalar内で安全な形にエスケープする（" \ および制御文字を処理）
void yaml_double_quote_escape(const char *src, char *dst, size_t dst_cap) {
    if (!dst || dst_cap == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t d = 0;
    for (size_t s = 0; src[s] != '\0' && d + 1 < dst_cap; s++) {
        unsigned char c = (unsigned char)src[s];
        if (c == '"' || c == '\\') {
            if (d + 2 >= dst_cap) break;
            dst[d++] = '\\';
            dst[d++] = (char)c;
        } else if (c < 0x20) {
            if (d + 4 >= dst_cap) break;
            d += (size_t)snprintf(dst + d, dst_cap - d, "\\x%02x", c);
        } else {
            dst[d++] = (char)c;
        }
    }
    dst[d] = '\0';
}

void print_response_yaml(const uint8_t *pkt, size_t pkt_len, const char *server, uint16_t port, bool is_tcp, const display_opts_t *dopt) {
    if (pkt_len < 12) return;
    uint16_t id = (pkt[0] << 8) | pkt[1];
    uint16_t flags = (pkt[2] << 8) | pkt[3];
    uint16_t qdcount = (pkt[4] << 8) | pkt[5];
    uint16_t ancount = (pkt[6] << 8) | pkt[7];
    uint16_t nscount = (pkt[8] << 8) | pkt[9];
    uint16_t arcount = (pkt[10] << 8) | pkt[11];

    bool qr = (flags >> 15) & 1;
    bool aa = (flags >> 10) & 1;
    bool tc = (flags >> 9) & 1;
    bool rd = (flags >> 8) & 1;
    bool ra = (flags >> 7) & 1;
    bool z  = (flags >> 6) & 1;
    bool ad = (flags >> 5) & 1;
    bool cd = (flags >> 4) & 1;
    uint8_t opcode = (flags >> 11) & 0xF;
    uint8_t rcode = flags & 0xF;

    time_t now = time(NULL);
    struct tm tm_utc;
    gmtime_r(&now, &tm_utc);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%S.000Z", &tm_utc);

    const char *resp_type = "RESPONSE";
    if (qr) {
        if (aa || !ra) resp_type = "AUTH_RESPONSE";
        else resp_type = "RECURSIVE_RESPONSE";
    } else {
        resp_type = "QUERY";
    }

    const char *family_str = (g_last_socket_family == AF_INET6) ? "INET6" : "INET";
    const char *proto_str = is_tcp ? "TCP" : "UDP";

    printf("- type: MESSAGE\n");
    printf("  message:\n");
    printf("    type: %s\n", resp_type);
    printf("    query_time: !!timestamp %s\n", time_str);
    printf("    response_time: !!timestamp %s\n", time_str);
    printf("    message_size: %zub\n", pkt_len);
    printf("    socket_family: %s\n", family_str);
    printf("    socket_protocol: %s\n", proto_str);
    printf("    response_address: \"%s\"\n", (g_last_server_ip[0] ? g_last_server_ip : (server ? server : "127.0.0.1")));
    printf("    response_port: %u\n", port ? port : 53);
    printf("    query_address: \"0.0.0.0\"\n");
    printf("    query_port: 0\n");
    printf("    response_message_data:\n");
    printf("      opcode: %s\n", opcode_name(opcode));
    printf("      status: %s\n", rcode_name(rcode));
    printf("      id: %u\n", id);

    printf("      flags:");
    if (qr) printf(" qr");
    if (aa) printf(" aa");
    if (tc) printf(" tc");
    if (rd) printf(" rd");
    if (ra) printf(" ra");
    if (z)  printf(" z");
    if (ad) printf(" ad");
    if (cd) printf(" cd");
    printf("\n");

    printf("      QUESTION: %u\n", qdcount);
    printf("      ANSWER: %u\n", ancount);
    printf("      AUTHORITY: %u\n", nscount);
    printf("      ADDITIONAL: %u\n", arcount);

    // Scan for OPT record in additional section
    size_t scan_off = 12;
    for (int i = 0; i < qdcount; i++) {
        size_t nxt;
        if (skip_wire_name(pkt, pkt_len, scan_off, &nxt) != 0) break;
        scan_off = nxt + 4;
        if (scan_off > pkt_len) break;
    }
    int non_qd_total = ancount + nscount + arcount;
    bool has_opt = false;
    uint8_t opt_ver = 0;
    uint16_t opt_udp = 0;
    uint16_t opt_ext_flags = 0;

    for (int i = 0; i < non_qd_total; i++) {
        if (scan_off >= pkt_len) break;
        char *rname = NULL;
        size_t nxt;
        if (expand_wire_name(pkt, pkt_len, scan_off, &nxt, &g_dag_arena, &rname) != 0) break;
        if (nxt + 10 > pkt_len) break;
        uint16_t type = (pkt[nxt] << 8) | pkt[nxt+1];
        uint16_t klass = (pkt[nxt+2] << 8) | pkt[nxt+3];
        uint32_t ttl = ((uint32_t)pkt[nxt+4]<<24)|((uint32_t)pkt[nxt+5]<<16)|((uint32_t)pkt[nxt+6]<<8)|pkt[nxt+7];
        uint16_t rdlen = (pkt[nxt+8] << 8) | pkt[nxt+9];
        size_t rdata_start = nxt + 10;
        if (rdata_start + rdlen > pkt_len) break;

        if (i >= ancount + nscount && type == 41) { // OPT in additional
            has_opt = true;
            opt_udp = klass;
            opt_ver = (ttl >> 16) & 0xFF;
            opt_ext_flags = (ttl & 0xFFFF);
            break;
        }
        scan_off = rdata_start + rdlen;
    }

    if (has_opt) {
        printf("      OPT_PSEUDOSECTION:\n");
        printf("        EDNS:\n");
        printf("          version: %u\n", opt_ver);
        printf("          flags:");
        if (opt_ext_flags & 0x8000) printf(" do");
        if (opt_ext_flags & 0x0040) printf(" co");
        printf("\n");
        printf("          udp: %u\n", opt_udp);

        size_t opt_scan_off = 12;
        for (int i = 0; i < qdcount; i++) {
            size_t nxt;
            if (skip_wire_name(pkt, pkt_len, opt_scan_off, &nxt) != 0) break;
            opt_scan_off = nxt + 4;
            if (opt_scan_off > pkt_len) break;
        }
        for (int i = 0; i < non_qd_total; i++) {
            if (opt_scan_off >= pkt_len) break;
            size_t nxt;
            if (skip_wire_name(pkt, pkt_len, opt_scan_off, &nxt) != 0) break;
            if (nxt + 10 > pkt_len) break;
            uint16_t type = (pkt[nxt] << 8) | pkt[nxt+1];
            uint16_t rdlen = (pkt[nxt+8] << 8) | pkt[nxt+9];
            size_t rdata_start = nxt + 10;
            if (rdata_start + rdlen > pkt_len) break;

            if (i >= ancount + nscount && type == 41) { // OPT in additional
                size_t p = rdata_start, end = rdata_start + rdlen;
                while (p + 4 <= end) {
                    uint16_t code = (pkt[p] << 8) | pkt[p+1];
                    uint16_t olen = (pkt[p+2] << 8) | pkt[p+3];
                    p += 4;
                    if (p + olen > end) break;
                    decode_and_print_edns_option(pkt, p, code, olen, "          ", dopt);
                    p += olen;
                }
            }
            opt_scan_off = rdata_start + rdlen;
        }
    }

    size_t offset = 12;
    if (qdcount > 0) {
        if (opcode == 5) {
            printf("      ZONE_SECTION:\n");
        } else {
            printf("      QUESTION_SECTION:\n");
        }
        for (int i = 0; i < qdcount; i++) {
            char *name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, offset, &next, &g_dag_arena, &name) != 0) break;
            if (next + 4 > pkt_len) break;
            uint16_t qtype = (pkt[next] << 8) | pkt[next+1];
            uint16_t qclass = (pkt[next+2] << 8) | pkt[next+3];
            char tname_buf[32];
            char cname_buf[16];
            char name_esc[512];
            yaml_single_quote_escape(name ? name : ".", name_esc, sizeof(name_esc));
            const char *tname = format_type_name(qtype, tname_buf, sizeof(tname_buf));
            const char *cname = format_class_name(qclass, cname_buf, sizeof(cname_buf));
            printf("        - '%s %s %s'\n", name_esc, cname, tname);
            offset = next + 4;
        }
    }

    struct { const char *section_yaml_name; int count; } sec_defs[] = {
        { (opcode == 5) ? "PREREQUISITE_SECTION" : "ANSWER_SECTION", ancount },
        { (opcode == 5) ? "UPDATE_SECTION" : "AUTHORITY_SECTION", nscount },
        { "ADDITIONAL_SECTION", arcount }
    };

    for (int s = 0; s < 3; s++) {
        if (sec_defs[s].count <= 0) continue;
        size_t sec_offset = offset;
        int non_opt_count = 0;
        for (int i = 0; i < sec_defs[s].count; i++) {
            char *name = NULL; size_t next;
            if (expand_wire_name(pkt, pkt_len, sec_offset, &next, &g_dag_arena, &name) != 0) break;
            if (next + 10 > pkt_len) break;
            uint16_t type = (pkt[next] << 8) | pkt[next+1];
            uint16_t rdlen = (pkt[next+8] << 8) | pkt[next+9];
            if (s != 2 || type != 41) non_opt_count++;
            sec_offset = next + 10 + rdlen;
        }

        if (non_opt_count > 0) {
            printf("      %s:\n", sec_defs[s].section_yaml_name);
            for (int i = 0; i < sec_defs[s].count; i++) {
                char *name = NULL; size_t next;
                if (expand_wire_name(pkt, pkt_len, offset, &next, &g_dag_arena, &name) != 0) break;
                if (next + 10 > pkt_len) break;
                uint16_t type = (pkt[next] << 8) | pkt[next+1];
                uint16_t klass = (pkt[next+2] << 8) | pkt[next+3];
                uint32_t ttl = ((uint32_t)pkt[next+4]<<24)|((uint32_t)pkt[next+5]<<16)|((uint32_t)pkt[next+6]<<8)|pkt[next+7];
                uint16_t rdlen = (pkt[next+8] << 8) | pkt[next+9];
                size_t rdata_start = next + 10;
                if (rdata_start + rdlen > pkt_len) break;

                if (type == 41 && s == 2) {
                    offset = rdata_start + rdlen;
                    continue;
                }

                char tname_buf[32];
                char cname_buf[16];
                char ttl_str[32];
                if (dopt && dopt->ttlunits) {
                    format_ttl_units(ttl, ttl_str, sizeof(ttl_str));
                } else {
                    snprintf(ttl_str, sizeof(ttl_str), "%u", ttl);
                }

                const char *tname = format_type_name(type, tname_buf, sizeof(tname_buf));
                const char *cname = format_class_name(klass, cname_buf, sizeof(cname_buf));

                static char rdata_raw[65536];
                format_rdata_for_display(pkt, pkt_len, type, rdata_start, rdlen, rdata_raw, sizeof(rdata_raw), dopt);

                char name_esc[512];
                static char rdata_esc[131072];
                yaml_single_quote_escape(name ? name : ".", name_esc, sizeof(name_esc));
                yaml_single_quote_escape(rdata_raw, rdata_esc, sizeof(rdata_esc));

                printf("        - '%s %s %s %s %s'\n", name_esc, ttl_str, cname, tname, rdata_esc);
                offset = rdata_start + rdlen;
            }
        } else {
            offset = sec_offset;
        }
    }
}

void print_response_yaml_dns64(const uint8_t *pkt, size_t pkt_len, const char *server, uint16_t port, bool is_tcp) {
    if (pkt_len < 12) return;
    uint16_t id = (pkt[0] << 8) | pkt[1];
    uint16_t flags = (pkt[2] << 8) | pkt[3];
    uint16_t qdcount = (pkt[4] << 8) | pkt[5];
    uint16_t ancount = (pkt[6] << 8) | pkt[7];
    uint16_t nscount = (pkt[8] << 8) | pkt[9];
    uint16_t arcount = (pkt[10] << 8) | pkt[11];

    bool qr = (flags >> 15) & 1;
    bool aa = (flags >> 10) & 1;
    bool tc = (flags >> 9) & 1;
    bool rd = (flags >> 8) & 1;
    bool ra = (flags >> 7) & 1;
    bool z  = (flags >> 6) & 1;
    bool ad = (flags >> 5) & 1;
    bool cd = (flags >> 4) & 1;
    uint8_t opcode = (flags >> 11) & 0xF;
    uint8_t rcode = flags & 0xF;

    time_t now = time(NULL);
    struct tm tm_utc;
    gmtime_r(&now, &tm_utc);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%S.000Z", &tm_utc);

    const char *resp_type = "RESPONSE";
    if (qr) {
        if (aa) resp_type = "AUTH_RESPONSE";
        else resp_type = "RECURSIVE_RESPONSE";
    } else {
        resp_type = "QUERY";
    }

    const char *family_str = (g_last_socket_family == AF_INET6) ? "INET6" : "INET";
    const char *proto_str = is_tcp ? "TCP" : "UDP";

    printf("- type: MESSAGE\n");
    printf("  message:\n");
    printf("    type: %s\n", resp_type);
    printf("    query_time: !!timestamp %s\n", time_str);
    printf("    response_time: !!timestamp %s\n", time_str);
    printf("    message_size: %zub\n", pkt_len);
    printf("    socket_family: %s\n", family_str);
    printf("    socket_protocol: %s\n", proto_str);
    printf("    response_address: \"%s\"\n", server ? server : "127.0.0.1");
    printf("    response_port: %u\n", port ? port : 53);
    printf("    query_address: \"0.0.0.0\"\n");
    printf("    query_port: 0\n");
    printf("    response_message_data:\n");
    printf("      opcode: %s\n", opcode_name(opcode));
    printf("      status: %s\n", rcode_name(rcode));
    printf("      id: %u\n", id);

    printf("      flags:");
    if (qr) printf(" qr");
    if (aa) printf(" aa");
    if (tc) printf(" tc");
    if (rd) printf(" rd");
    if (ra) printf(" ra");
    if (z)  printf(" z");
    if (ad) printf(" ad");
    if (cd) printf(" cd");
    printf("\n");

    printf("      QUESTION: %u\n", qdcount);
    printf("      ANSWER: %u\n", ancount);
    printf("      AUTHORITY: %u\n", nscount);
    printf("      ADDITIONAL: %u\n", arcount);
}

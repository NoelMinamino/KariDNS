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

/* dig と同じ "2026-10-06T06:49:22.489Z" (UTC、ミリ秒まで)。t が未設定なら現在時刻 */
static void yaml_timestamp(const struct timespec *t, char *out, size_t cap) {
    struct timespec now;
    if (!t || t->tv_sec == 0) {
        clock_gettime(CLOCK_REALTIME, &now);
        t = &now;
    }
    time_t sec = t->tv_sec;
    struct tm tm_utc;
    gmtime_r(&sec, &tm_utc);
    char base[48];
    strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &tm_utc);
    snprintf(out, cap, "%s.%03ldZ", base, (long)(t->tv_nsec / 1000000));
}

/* pkt が dag の送ったクエリ (dopt->msg_is_query) なら dig +qr +yaml と同じく
 * RECURSIVE_QUERY / AUTH_QUERY と query_message_data で出す。セクションは +[no]question 等と
 * +[no]comments (OPT_PSEUDOSECTION) に従う。 */
void print_response_yaml(const uint8_t *pkt, size_t pkt_len, const char *server, uint16_t port, bool is_tcp, const display_opts_t *dopt) {
    if (pkt_len < 12) return;
    bool is_query = dopt && dopt->msg_is_query;
    bool show_comments = !dopt || dopt->show_comments;
    bool show_question = !dopt || dopt->show_question;
    bool show_sec[3] = { !dopt || dopt->show_answer, !dopt || dopt->show_authority, !dopt || dopt->show_additional };
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
    uint16_t rcode = flags & 0xF;

    const char *msg_type;
    if (is_query) msg_type = rd ? "RECURSIVE_QUERY" : "AUTH_QUERY";
    else if (aa || !ra) msg_type = "AUTH_RESPONSE";
    else msg_type = "RECURSIVE_RESPONSE";

    const char *family_str = (g_last_socket_family == AF_INET6) ? "INET6" : "INET";
    const char *proto_str = is_tcp ? "TCP" : "UDP";
    char qtime[64], rtime[64];
    yaml_timestamp(&g_dag_query_time, qtime, sizeof(qtime));
    yaml_timestamp(&g_dag_response_time, rtime, sizeof(rtime));

    /* OPT を先に探す: 拡張 RCODE (TTL の上位 8 ビット, RFC 6891 §6.1.3) を status に含めるため */
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
    size_t opt_rdata = 0;
    uint16_t opt_rdlen = 0;

    for (int i = 0; i < non_qd_total; i++) {
        if (scan_off >= pkt_len) break;
        size_t nxt;
        if (skip_wire_name(pkt, pkt_len, scan_off, &nxt) != 0) break;
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
            rcode |= (uint16_t)(((ttl >> 24) & 0xFF) << 4);
            opt_ver = (ttl >> 16) & 0xFF;
            opt_ext_flags = (ttl & 0xFFFF);
            opt_rdata = rdata_start;
            opt_rdlen = rdlen;
            break;
        }
        scan_off = rdata_start + rdlen;
    }

    printf("- type: MESSAGE\n");
    printf("  message:\n");
    printf("    type: %s\n", msg_type);
    printf("    query_time: !!timestamp %s\n", qtime);
    if (!is_query) printf("    response_time: !!timestamp %s\n", rtime);
    printf("    message_size: %zub\n", pkt_len);
    printf("    socket_family: %s\n", family_str);
    printf("    socket_protocol: %s\n", proto_str);
    printf("    response_address: \"%s\"\n", (g_last_server_ip[0] ? g_last_server_ip : (server ? server : "127.0.0.1")));
    printf("    response_port: %u\n", port ? port : 53);
    printf("    query_address: \"0.0.0.0\"\n");
    printf("    query_port: 0\n");
    printf("    %s_message_data:\n", is_query ? "query" : "response");
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

    if (has_opt && show_comments) {
        printf("      OPT_PSEUDOSECTION:\n");
        printf("        EDNS:\n");
        printf("          version: %u\n", opt_ver);
        printf("          flags:");
        if (opt_ext_flags & 0x8000) printf(" do");
        if (opt_ext_flags & 0x4000) printf(" co");
        printf("\n");
        printf("          udp: %u\n", opt_udp);
        size_t p = opt_rdata, end = opt_rdata + opt_rdlen;
        while (p + 4 <= end) {
            uint16_t code = (pkt[p] << 8) | pkt[p+1];
            uint16_t olen = (pkt[p+2] << 8) | pkt[p+3];
            p += 4;
            if (p + olen > end) break;
            decode_and_print_edns_option(pkt, p, code, olen, "          ", dopt);
            p += olen;
        }
    }

    size_t offset = 12;
    if (qdcount > 0) {
        if (show_question) printf("      %s:\n", (opcode == 5) ? "ZONE_SECTION" : "QUESTION_SECTION");
        for (int i = 0; i < qdcount; i++) {
            char *name = NULL; size_t next;
            if (dag_expand_name(pkt, pkt_len, offset, &next, &g_dag_arena, &name) != 0) break;
            if (next + 4 > pkt_len) break;
            uint16_t qtype = (pkt[next] << 8) | pkt[next+1];
            uint16_t qclass = (pkt[next+2] << 8) | pkt[next+3];
            offset = next + 4;
            if (!show_question) continue;
            char tname_buf[32];
            char cname_buf[16];
            char name_esc[DNS_NAME_TEXT_SIZE * 2];
            yaml_single_quote_escape(name ? name : ".", name_esc, sizeof(name_esc));
            const char *tname = format_type_name(qtype, tname_buf, sizeof(tname_buf));
            const char *cname = format_class_name(qclass, cname_buf, sizeof(cname_buf));
            printf("        - '%s %s %s'\n", name_esc, cname, tname);
        }
    }

    struct { const char *section_yaml_name; int count; } sec_defs[] = {
        { (opcode == 5) ? "PREREQUISITE_SECTION" : "ANSWER_SECTION", ancount },
        { (opcode == 5) ? "UPDATE_SECTION" : "AUTHORITY_SECTION", nscount },
        { "ADDITIONAL_SECTION", arcount }
    };

    /* ADDITIONAL の最後の TSIG/SIG(0) は dig と同じく TSIG_PSEUDOSECTION / SIG0_PSEUDOSECTION に出す */
    size_t sig_off = 0;
    const char *sig_label = NULL;
    char sig_line[DNS_NAME_TEXT_SIZE * 2 + 1024] = "";

    for (int s = 0; s < 3; s++) {
        if (sec_defs[s].count <= 0) continue;
        if (s == 2) sig_label = find_sig_pseudo_rr(pkt, pkt_len, offset, arcount, &sig_off);
        size_t sec_offset = offset;
        int non_opt_count = 0;
        for (int i = 0; i < sec_defs[s].count; i++) {
            size_t next;
            if (skip_wire_name(pkt, pkt_len, sec_offset, &next) != 0) break;
            if (next + 10 > pkt_len) break;
            uint16_t type = (pkt[next] << 8) | pkt[next+1];
            uint16_t rdlen = (pkt[next+8] << 8) | pkt[next+9];
            if (s != 2 || (type != 41 && !(sig_label && sec_offset == sig_off))) non_opt_count++;
            sec_offset = next + 10 + rdlen;
        }
        if (s == 2 && sig_label) {
            char *name = NULL;
            size_t next;
            if (dag_expand_name(pkt, pkt_len, sig_off, &next, &g_dag_arena, &name) == 0 && next + 10 <= pkt_len) {
                uint16_t type = (pkt[next] << 8) | pkt[next+1];
                uint16_t klass = (pkt[next+2] << 8) | pkt[next+3];
                uint32_t ttl = ((uint32_t)pkt[next+4]<<24)|((uint32_t)pkt[next+5]<<16)|((uint32_t)pkt[next+6]<<8)|pkt[next+7];
                uint16_t rdlen = (pkt[next+8] << 8) | pkt[next+9];
                char tname_buf[32], cname_buf[16];
                static char sig_rdata[65536];
                format_rdata_for_display(pkt, pkt_len, type, next + 10, rdlen, sig_rdata, sizeof(sig_rdata), dopt);
                char raw[sizeof(sig_line)];
                snprintf(raw, sizeof(raw), "%s %u %s %s %s", name, ttl, format_class_name(klass, cname_buf, sizeof(cname_buf)),
                         format_type_name(type, tname_buf, sizeof(tname_buf)), sig_rdata);
                yaml_single_quote_escape(raw, sig_line, sizeof(sig_line));
            }
        }

        if (non_opt_count > 0 && show_sec[s]) {
            printf("      %s:\n", sec_defs[s].section_yaml_name);
            for (int i = 0; i < sec_defs[s].count; i++) {
                char *name = NULL; size_t next;
                size_t rr_start = offset;
                if (dag_expand_name(pkt, pkt_len, offset, &next, &g_dag_arena, &name) != 0) break;
                if (next + 10 > pkt_len) break;
                uint16_t type = (pkt[next] << 8) | pkt[next+1];
                uint16_t klass = (pkt[next+2] << 8) | pkt[next+3];
                uint32_t ttl = ((uint32_t)pkt[next+4]<<24)|((uint32_t)pkt[next+5]<<16)|((uint32_t)pkt[next+6]<<8)|pkt[next+7];
                uint16_t rdlen = (pkt[next+8] << 8) | pkt[next+9];
                size_t rdata_start = next + 10;
                if (rdata_start + rdlen > pkt_len) break;

                if (s == 2 && (type == 41 || (sig_label && rr_start == sig_off))) {
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
                g_dag_rdata_class = klass;
                format_rdata_for_display(pkt, pkt_len, type, rdata_start, rdlen, rdata_raw, sizeof(rdata_raw), dopt);
                g_dag_rdata_class = 1;

                char name_esc[DNS_NAME_TEXT_SIZE * 2];
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
    if (sig_label && sig_line[0] && show_sec[2]) {
        printf("      %s_PSEUDOSECTION:\n", sig_label);
        printf("      - '%s'\n\n", sig_line); /* dig leaves an empty line after it */
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

    char qtime[64], rtime[64];
    yaml_timestamp(&g_dag_query_time, qtime, sizeof(qtime));
    yaml_timestamp(&g_dag_response_time, rtime, sizeof(rtime));

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
    printf("    query_time: !!timestamp %s\n", qtime);
    printf("    response_time: !!timestamp %s\n", rtime);
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

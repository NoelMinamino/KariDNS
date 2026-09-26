#include "dag_edns_client.h"
#include "dag_output_yaml.h"

break_opt_t g_breaks[MAX_BREAKS];
int g_break_count = 0;

bool is_structural_break(break_kind_t k) {
    switch (k) {
        case BRK_COMPRESSION_LOOP:
        case BRK_COMPRESSION_FORWARD:
        case BRK_LABEL_TOO_LONG:
        case BRK_RESERVED_LENGTH_BITS:
        case BRK_OVERSIZED_QNAME:
        case BRK_TRUNCATED_QUESTION:
        case BRK_NOTIFY_NO_QUESTION:
            return true;
        default:
            return false;
    }
}

bool is_tcp_only_break(break_kind_t k) {
    return k == BRK_TCP_LENGTH_OVERCLAIM || k == BRK_TCP_ZERO_LENGTH || k == BRK_TCP_IDLE_HOLD;
}

bool has_break(break_kind_t kind, long *param_out, bool *has_param_out) {
    for (int i = 0; i < g_break_count; i++) {
        if (g_breaks[i].kind == kind) {
            if (param_out) *param_out = g_breaks[i].param;
            if (has_param_out) *has_param_out = g_breaks[i].has_param;
            return true;
        }
    }
    return false;
}

bool any_structural_break(break_kind_t *which_out) {
    for (int i = 0; i < g_break_count; i++) {
        if (is_structural_break(g_breaks[i].kind)) {
            if (which_out) *which_out = g_breaks[i].kind;
            return true;
        }
    }
    return false;
}

void parse_break_arg(const char *arg) {
    char name[64]; long param = 0; bool has_param = false;
    const char *eq = strchr(arg, '=');
    if (eq) {
        size_t nlen = (size_t)(eq - arg);
        if (nlen >= sizeof(name)) nlen = sizeof(name) - 1;
        memcpy(name, arg, nlen); name[nlen] = '\0';
        param = strtol(eq + 1, NULL, 0);
        has_param = true;
    } else {
        strncpy(name, arg, sizeof(name) - 1); name[sizeof(name) - 1] = '\0';
    }

    break_kind_t kind = BRK_NONE;
    if      (strcmp(name, "compression-loop") == 0)     kind = BRK_COMPRESSION_LOOP;
    else if (strcmp(name, "compression-forward") == 0)  kind = BRK_COMPRESSION_FORWARD;
    else if (strcmp(name, "label-too-long") == 0)        { kind = BRK_LABEL_TOO_LONG; if (!has_param) { param = 100; has_param = true; } }
    else if (strcmp(name, "reserved-length-bits") == 0)  kind = BRK_RESERVED_LENGTH_BITS;
    else if (strcmp(name, "oversized-qname") == 0)       kind = BRK_OVERSIZED_QNAME;
    else if (strcmp(name, "qdcount") == 0)               kind = BRK_QDCOUNT;
    else if (strcmp(name, "truncated-question") == 0)    kind = BRK_TRUNCATED_QUESTION;
    else if (strcmp(name, "opt-rdlen") == 0)              kind = BRK_OPT_RDLEN;
    else if (strcmp(name, "arcount") == 0)                kind = BRK_ARCOUNT;
    else if (strcmp(name, "opcode") == 0)                 kind = BRK_OPCODE;
    else if (strcmp(name, "qr-bit") == 0)                 kind = BRK_QR_BIT;
    else if (strcmp(name, "notify-no-question") == 0)     kind = BRK_NOTIFY_NO_QUESTION;
    else if (strcmp(name, "too-short") == 0 || strcmp(name, "short-header") == 0) {
        kind = BRK_TOO_SHORT;
        if (!has_param) { param = 3; has_param = true; }
    }
    else if (strcmp(name, "tcp-length-overclaim") == 0)   { kind = BRK_TCP_LENGTH_OVERCLAIM; if (!has_param) { param = 10; has_param = true; } }
    else if (strcmp(name, "tcp-zero-length") == 0)        kind = BRK_TCP_ZERO_LENGTH;
    else if (strcmp(name, "tcp-idle-hold") == 0)          { kind = BRK_TCP_IDLE_HOLD; if (!has_param) { param = 20; has_param = true; } }
    else if (strcmp(name, "update-meta-type") == 0)       { kind = BRK_UPDATE_META_TYPE; if (!has_param) { param = 41; has_param = true; } }
    else {
        fprintf(stderr, "warning: unknown --break kind '%s', ignoring\n", name);
        return;
    }

    // Check if the same break kind is already registered; if so, override parameter
    for (int i = 0; i < g_break_count; i++) {
        if (g_breaks[i].kind == kind) {
            fprintf(stderr, ";; note: --break '%s' overrides previous value for this kind (was param=%ld, now param=%ld)\n",
                    name, g_breaks[i].param, param);
            g_breaks[i].param = param;
            g_breaks[i].has_param = has_param;
            return;
        }
    }

    if (is_structural_break(kind)) {
        break_kind_t existing;
        if (any_structural_break(&existing) && existing != kind) {
            fprintf(stderr,
                "warning: --break '%s' ignored; structural break kind is already set "
                "and only one structural break can be active per query (see --break-help)\n",
                name);
            return;
        }
    }

    if (g_break_count >= MAX_BREAKS) {
        fprintf(stderr, "warning: too many --break options, ignoring '%s'\n", arg);
        return;
    }

    g_breaks[g_break_count].kind = kind;
    g_breaks[g_break_count].param = param;
    g_breaks[g_break_count].has_param = has_param;
    g_break_count++;
}

void print_break_help(void) {
    printf(
        "NOTE: Only one *structural* --break kind (compression-loop, compression-forward,\n"
        "      label-too-long, reserved-length-bits, oversized-qname, truncated-question,\n"
        "      notify-no-question) can be active per query. If multiple are specified, only\n"
        "      the first one takes effect; TCP-only and header-flag breaks can still be\n"
        "      combined freely with a structural break.\n\n"
        "--break kinds:\n"
        "  compression-loop           question name = self-referencing compression pointer\n"
        "  compression-forward        question name = pointer to an unseen forward offset\n"
        "  label-too-long[=N]         label length byte N (63<N<192), default 100\n"
        "  reserved-length-bits       label length byte 0x40 (reserved bit pattern)\n"
        "  oversized-qname            QNAME > 255 bytes via many short labels\n"
        "  qdcount=N                  override header QDCOUNT\n"
        "  truncated-question         cut the packet mid-label\n"
        "  opt-rdlen=N                lie about the OPT record's RDLENGTH (forces OPT)\n"
        "  arcount=N                  override header ARCOUNT\n"
        "  opcode=N                   override header OPCODE\n"
        "  qr-bit                     set QR=1 on an outgoing query\n"
        "  notify-no-question         OPCODE=4 (NOTIFY) with QDCOUNT=0, no question\n"
        "  too-short[=N]              send only the first N bytes of the message (default 3)\n"
        "  short-header[=N]           alias for too-short[=N]\n"
        "  tcp-length-overclaim[=N]   (--tcp only) length prefix N bytes bigger than body sent (default 10)\n"
        "  tcp-zero-length            (--tcp only) send a 0 length prefix\n"
        "  tcp-idle-hold[=SEC]        (--tcp only) send only the length prefix, hold the\n"
        "                             connection, report when/if the server disconnects (default 20)\n"
        "  update-meta-type[=N]       (UPDATE only) inject a meta-type RR (default 41) into Update Section\n"
    );
}


const char *dnssec_algo_name(uint8_t alg) {
    switch (alg) {
        case 1: return "RSAMD5";
        case 2: return "DH";
        case 3: return "DSA";
        case 5: return "RSASHA1";
        case 6: return "DSA-NSEC3-SHA1";
        case 7: return "RSASHA1-NSEC3-SHA1";
        case 8: return "RSASHA256";
        case 10: return "RSASHA512";
        case 12: return "ECC-GOST";
        case 13: return "ECDSAP256SHA256";
        case 14: return "ECDSAP384SHA384";
        case 15: return "ED25519";
        case 16: return "ED448";
        default: return "UNKNOWN";
    }
}


bool parse_subnet_arg(const char *arg, query_opts_t *qo) {
    if (!arg || !*arg) return false;
    // RFC 7871 §5: +subnet=0 または +subnet=0/0 によるECS無効化/プライバシー要求
    if (strcmp(arg, "0") == 0 || strcmp(arg, "0/0") == 0 || strcmp(arg, "0.0.0.0/0") == 0) {
        qo->subnet_family = 1;
        memset(qo->subnet_addr, 0, sizeof(qo->subnet_addr));
        qo->subnet_prefix = 0;
        return true;
    }
    if (strcmp(arg, "::/0") == 0) {
        qo->subnet_family = 2;
        memset(qo->subnet_addr, 0, sizeof(qo->subnet_addr));
        qo->subnet_prefix = 0;
        return true;
    }

    char buf[128];
    strncpy(buf, arg, sizeof(buf) - 1); buf[sizeof(buf) - 1] = '\0';
    char *slash = strchr(buf, '/');
    int prefix = -1;
    if (slash) {
        *slash = '\0';
        char *endptr;
        long pfx_val = strtol(slash + 1, &endptr, 10);
        if (*endptr == '\0' && pfx_val >= 0) prefix = (int)pfx_val;
    }

    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, buf, &a4) == 1) {
        qo->subnet_family = 1;
        memcpy(qo->subnet_addr, &a4, 4);
        qo->subnet_prefix = (prefix >= 0) ? prefix : 24;
        if (qo->subnet_prefix > 32) qo->subnet_prefix = 32;
        return true;
    }
    if (inet_pton(AF_INET6, buf, &a6) == 1) {
        qo->subnet_family = 2;
        memcpy(qo->subnet_addr, &a6, 16);
        qo->subnet_prefix = (prefix >= 0) ? prefix : 56;
        if (qo->subnet_prefix > 128) qo->subnet_prefix = 128;
        return true;
    }
    fprintf(stderr, "invalid +subnet address: %s\n", arg);
    return false;
}

uint16_t build_opt_record(uint8_t *pkt, size_t max_len, uint16_t offset,
                                  const query_opts_t *qo, uint16_t *opt_rdlen_field_out) {
    if ((size_t)offset + 1 > max_len) return offset;
    pkt[offset++] = 0x00; /* Root name */

    if ((size_t)offset + 10 > max_len) return offset;
    pkt[offset++] = 0x00; pkt[offset++] = 41; /* TYPE = OPT */
    pkt[offset++] = qo->udp_payload_size >> 8; pkt[offset++] = qo->udp_payload_size & 0xFF;
    pkt[offset++] = 0x00; /* extended RCODE */
    pkt[offset++] = qo->edns_version; /* version */
    uint16_t flags = 0;
    if (qo->dnssec_ok) flags |= 0x8000;
    if (qo->compact_answers_ok) flags |= 0x4000;
    if (qo->ednsflags_z) flags |= qo->ednsflags_z;
    pkt[offset++] = flags >> 8; pkt[offset++] = flags & 0xFF;

    uint16_t rdlen_field_offset = offset;
    pkt[offset++] = 0x00; pkt[offset++] = 0x00; /* RDLENGTH placeholder */
    uint16_t rdata_start = offset;

    if (qo->want_nsid) {
        if ((size_t)offset + 4 > max_len) goto done;
        pkt[offset++] = 0x00; pkt[offset++] = 0x03; /* OPTION-CODE = NSID */
        pkt[offset++] = 0x00; pkt[offset++] = 0x00; /* OPTION-LENGTH = 0 (empty request) */
    }

    if (qo->want_expire_opt) {
        if ((size_t)offset + 4 <= max_len) {
            pkt[offset++] = 0x00; pkt[offset++] = 0x09; /* OPTION-CODE = EDNS EXPIRE (RFC 7314) */
            pkt[offset++] = 0x00; pkt[offset++] = 0x00; /* OPTION-LENGTH = 0 */
        }
    }

    if (qo->send_keepalive) {
        if ((size_t)offset + 4 <= max_len) {
            pkt[offset++] = 0x00; pkt[offset++] = 11; /* OPTION-CODE = edns-tcp-keepalive */
            pkt[offset++] = 0x00; pkt[offset++] = 0x00; /* OPTION-LENGTH = 0 */
        }
    }

    if (qo->want_cookie) {
        uint16_t opt_len = 8 + (uint16_t)qo->server_cookie_len;
        if ((size_t)offset + 4 + opt_len > max_len) goto done;
        pkt[offset++] = 0x00; pkt[offset++] = 0x0A; /* OPTION-CODE = COOKIE */
        pkt[offset++] = opt_len >> 8; pkt[offset++] = opt_len & 0xFF;
        memcpy(&pkt[offset], qo->client_cookie, 8); offset += 8;
        if (qo->server_cookie_len > 0) {
            memcpy(&pkt[offset], qo->server_cookie, qo->server_cookie_len);
            offset += qo->server_cookie_len;
        }
    }

    if (qo->want_subnet) {
        int addr_bytes = (qo->subnet_prefix + 7) / 8;
        uint16_t opt_len = 4 + (uint16_t)addr_bytes;
        if ((size_t)offset + 4 + opt_len > max_len) goto done;
        pkt[offset++] = 0x00; pkt[offset++] = 0x08; /* OPTION-CODE = ECS */
        pkt[offset++] = opt_len >> 8; pkt[offset++] = opt_len & 0xFF;
        pkt[offset++] = 0x00; pkt[offset++] = (qo->subnet_family == 2) ? 0x02 : 0x01; /* FAMILY */
        pkt[offset++] = (uint8_t)qo->subnet_prefix; /* SOURCE PREFIX-LENGTH */
        pkt[offset++] = 0x00;                        /* SCOPE PREFIX-LENGTH */
        uint8_t addr_copy[16];
        memcpy(addr_copy, qo->subnet_addr, 16);
        int total_bits = qo->subnet_prefix;
        for (int b = 0; b < addr_bytes; b++) {
            int bits_in_byte = total_bits - b * 8;
            if (bits_in_byte < 8) {
                uint8_t mask = (bits_in_byte <= 0) ? 0x00 : (uint8_t)(0xFF << (8 - bits_in_byte));
                addr_copy[b] &= mask;
            }
        }
        memcpy(&pkt[offset], addr_copy, addr_bytes);
        offset += addr_bytes;
    }

    for (int i = 0; i < qo->custom_edns_opt_count; i++) {
        if ((size_t)offset + 4 + qo->custom_edns_opts[i].len > max_len) break;
        pkt[offset++] = qo->custom_edns_opts[i].code >> 8;
        pkt[offset++] = qo->custom_edns_opts[i].code & 0xFF;
        pkt[offset++] = qo->custom_edns_opts[i].len >> 8;
        pkt[offset++] = qo->custom_edns_opts[i].len & 0xFF;
        if (qo->custom_edns_opts[i].len > 0) {
            memcpy(&pkt[offset], qo->custom_edns_opts[i].data, qo->custom_edns_opts[i].len);
            offset += qo->custom_edns_opts[i].len;
        }
    }

    if (qo->want_padding) {
        int block_size = (qo->padding_size > 0) ? qo->padding_size : 468;
        // Paddingオプションヘッダ(4バイト)を含めた現在長から、ブロック境界に必要なパディング長を算出
        size_t current_len = (size_t)offset + 4;
        if (qo->want_tsig) {
            // 付与予定のTSIGレコード長を見積もり（TSIG RRヘッダ＋アルゴリズム名＋MACサイズ＋固定フィールド）
            size_t tsig_keyname_len = qo->tsig_key.name ? strlen(qo->tsig_key.name) + 2 : 10;
            size_t tsig_alg_len = qo->tsig_key.algorithm ? strlen(qo->tsig_key.algorithm) + 2 : 15;
            size_t tsig_mac_len = 32; // HMAC-SHA256 (default)
            if (qo->tsig_key.algorithm) {
                if (dag_strcasestr(qo->tsig_key.algorithm, "sha512") || dag_strcasestr(qo->tsig_key.algorithm, "sha384")) tsig_mac_len = 64;
                else if (dag_strcasestr(qo->tsig_key.algorithm, "md5") || dag_strcasestr(qo->tsig_key.algorithm, "sha1")) tsig_mac_len = 20;
            }
            size_t tsig_estimated_len = tsig_keyname_len + 10 + tsig_alg_len + 6 + 2 + 2 + tsig_mac_len + 2 + 2 + 2;
            current_len += tsig_estimated_len;
        }
        size_t pad_len = (block_size - (current_len % block_size)) % block_size;
        if ((size_t)offset + 4 + pad_len <= max_len) {
            pkt[offset++] = 0x00; pkt[offset++] = 0x0C; // Option Code: 12 (Padding)
            pkt[offset++] = (uint16_t)pad_len >> 8;
            pkt[offset++] = (uint16_t)pad_len & 0xFF;
            if (pad_len > 0) {
                memset(&pkt[offset], 0, pad_len);
                offset += (uint16_t)pad_len;
            }
        }
    }

done:
    {
        uint16_t rdlen = offset - rdata_start;
        pkt[rdlen_field_offset] = rdlen >> 8;
        pkt[rdlen_field_offset + 1] = rdlen & 0xFF;
    }
    if (opt_rdlen_field_out) *opt_rdlen_field_out = rdlen_field_offset;
    return offset;
}

/* ========================================================================
 * 5. Packet construction (normal path + structural --break variants)
 * ==================================================================== */
size_t build_query_packet(uint8_t *pkt, size_t max_len,
                                  const char *qname, uint16_t qtype,
                                  const query_opts_t *qo) {
    if (qo->update_op_count > 0 || qo->prereq_count > 0 || has_break(BRK_UPDATE_META_TYPE, NULL, NULL)) {
        qtype = 6; /* SOA for Zone section */
    }

    memset(pkt, 0, 12);
    uint16_t id = (qo->qid_override >= 0) ? (uint16_t)(qo->qid_override & 0xFFFF) : qo->query_id;
    pkt[0] = id >> 8; pkt[1] = id & 0xFF;
    pkt[2] = qo->rd_flag ? 0x01 : 0x00;
    if (qo->aa_flag) pkt[2] |= 0x04;
    if (qo->tc_flag) pkt[2] |= 0x02;
    if (qo->ra_flag) pkt[3] |= 0x80;
    if (qo->ad_flag) pkt[3] |= 0x20;
    if (qo->cd_flag) pkt[3] |= 0x10;
    if (qo->z_flag)  pkt[3] |= 0x40;

    if (qo->opcode_override >= 0) {
        pkt[2] = (pkt[2] & 0x87) | ((qo->opcode_override & 0x0F) << 3);
    }

    if (qo->header_only) {
        pkt[4] = 0x00; pkt[5] = 0x00; /* QDCOUNT=0 */
    } else {
        pkt[4] = 0x00; pkt[5] = 0x01; /* QDCOUNT=1 (may be overridden below) */
    }

    if (qo->update_op_count > 0 || qo->prereq_count > 0 || has_break(BRK_UPDATE_META_TYPE, NULL, NULL)) {
        pkt[2] = (pkt[2] & 0x87) | (5 << 3); /* OPCODE=5 (UPDATE) */
    }

    break_kind_t structural = BRK_NONE;
    bool has_structural = any_structural_break(&structural);

    uint16_t offset = 12;

    if (qo->header_only || (has_structural && structural == BRK_NOTIFY_NO_QUESTION)) {
        pkt[4] = 0x00; pkt[5] = 0x00; /* QDCOUNT=0, no question bytes at all */
        if (!qo->header_only) {
            pkt[2] = (pkt[2] & 0x87) | (4 << 3); /* OPCODE=4 (NOTIFY) */
        }
    } else if (has_structural && structural == BRK_COMPRESSION_LOOP) {
        pkt[offset++] = 0xC0; pkt[offset++] = 0x0C;
        pkt[offset++] = qtype >> 8; pkt[offset++] = qtype & 0xFF;
        pkt[offset++] = 0x00; pkt[offset++] = 0x01;
    } else if (has_structural && structural == BRK_COMPRESSION_FORWARD) {
        pkt[offset++] = 0xC0; pkt[offset++] = 0xFF;
        pkt[offset++] = qtype >> 8; pkt[offset++] = qtype & 0xFF;
        pkt[offset++] = 0x00; pkt[offset++] = 0x01;
    } else if (has_structural && structural == BRK_LABEL_TOO_LONG) {
        long n = 100; has_break(BRK_LABEL_TOO_LONG, &n, NULL);
        pkt[offset++] = (uint8_t)n;
        int filler = (n < 20) ? (int)n : 20;
        for (int i = 0; i < filler; i++) pkt[offset++] = 'A';
        pkt[offset++] = 0x00;
        pkt[offset++] = qtype >> 8; pkt[offset++] = qtype & 0xFF;
        pkt[offset++] = 0x00; pkt[offset++] = 0x01;
    } else if (has_structural && structural == BRK_RESERVED_LENGTH_BITS) {
        pkt[offset++] = 0x40;
        for (int i = 0; i < 20; i++) pkt[offset++] = 'B';
        pkt[offset++] = 0x00;
        pkt[offset++] = qtype >> 8; pkt[offset++] = qtype & 0xFF;
        pkt[offset++] = 0x00; pkt[offset++] = 0x01;
    } else if (has_structural && structural == BRK_OVERSIZED_QNAME) {
        for (int i = 0; i < 60; i++) { pkt[offset++] = 4; memcpy(&pkt[offset], "aaaa", 4); offset += 4; }
        pkt[offset++] = 0x00;
        pkt[offset++] = qtype >> 8; pkt[offset++] = qtype & 0xFF;
        pkt[offset++] = 0x00; pkt[offset++] = 0x01;
    } else if (has_structural && structural == BRK_TRUNCATED_QUESTION) {
        pkt[offset++] = 0x05;
        memcpy(&pkt[offset], "www", 3); offset += 3;
        return offset;
    } else {
        compress_ctx_t comp_ctx = {0};
        compress_ctx_init_packet(&comp_ctx);
        if (write_dns_name_str(pkt, &offset, qname, &comp_ctx, max_len) != 0) {
            fprintf(stderr, "write_dns_name_str failed (name too long?)\n");
            return 0;
        }
        pkt[offset++] = qtype >> 8; pkt[offset++] = qtype & 0xFF;
        pkt[offset++] = qo->qclass >> 8; pkt[offset++] = qo->qclass & 0xFF;
    }

    if (qo->is_ixfr) {
        compress_ctx_t comp_ctx = {0};
        compress_ctx_init_packet(&comp_ctx);
        if (write_dns_name_str(pkt, &offset, qname, &comp_ctx, max_len) == 0) {
            pkt[offset++] = 0x00; pkt[offset++] = 0x06; /* Type SOA */
            pkt[offset++] = 0x00; pkt[offset++] = 0x01; /* Class IN */
            pkt[offset++] = 0x00; pkt[offset++] = 0x00; pkt[offset++] = 0x00; pkt[offset++] = 0x00; /* TTL 0 */
            pkt[offset++] = 0x00; pkt[offset++] = 0x16; /* RDLEN 22 */
            pkt[offset++] = 0x00; /* MNAME (.) */
            pkt[offset++] = 0x00; /* RNAME (.) */
            pkt[offset++] = (qo->ixfr_serial >> 24) & 0xFF;
            pkt[offset++] = (qo->ixfr_serial >> 16) & 0xFF;
            pkt[offset++] = (qo->ixfr_serial >> 8) & 0xFF;
            pkt[offset++] = qo->ixfr_serial & 0xFF; /* SERIAL */
            for (int i = 0; i < 16; i++) pkt[offset++] = 0; /* REFRESH, RETRY, EXPIRE, MINIMUM */
            
            uint16_t nscount = (pkt[8] << 8) | pkt[9];
            nscount++;
            pkt[8] = nscount >> 8; pkt[9] = nscount & 0xFF;
        }
    }

    if (qo->prereq_count > 0) {
        compress_ctx_t comp_ctx = {0};
        compress_ctx_init_packet(&comp_ctx);

        for (int pi = 0; pi < qo->prereq_count; pi++) {
            const char *name = qo->prereqs[pi].name;
            uint16_t type, class_val;

            if (qo->prereqs[pi].kind == PREREQ_YXRRSET && qo->prereqs[pi].rdata[0] != '\0') {
                // RFC 2136 Section 2.4.2: RRset Exists (Value Dependent)
                char *buf = strdup(qo->prereqs[pi].rdata);
                char *tokens[32];
                int token_count = 0;
                bool in_quote = false;
                char *p = buf;
                char *tok_start = NULL;
                char *out = buf;

                while (*p && token_count < 32) {
                    if (*p == '"') {
                        in_quote = !in_quote;
                        if (!tok_start) tok_start = out;
                        p++;
                    } else if (*p == ' ' && !in_quote) {
                        if (tok_start) {
                            *out++ = '\0';
                            tokens[token_count++] = tok_start;
                            tok_start = NULL;
                        }
                        p++;
                    } else {
                        if (!tok_start) tok_start = out;
                        if (*p == '\\' && *(p+1) == '"') {
                            p++;
                            *out++ = *p++;
                        } else {
                            *out++ = *p++;
                        }
                    }
                }
                if (tok_start && token_count < 32) {
                    *out = '\0';
                    tokens[token_count++] = tok_start;
                }

                if (!resolve_qtype(qo->prereqs[pi].type_str, &type)) {
                    fprintf(stderr, "warning: unknown record type '%s' in prereq yxrrset, skipping\n", qo->prereqs[pi].type_str);
                    free(buf);
                    continue;
                }
                dns_record_t rec;
                memset(&rec, 0, sizeof(rec));
                rec.name = (char *)name;
                rec.ttl = (char *)"0";
                rec.type_code = type;
                rec.type = (char *)qo->prereqs[pi].type_str;
                rec.class_str = (char *)(qo->qclass == 3 ? "CH" : (qo->qclass == 4 ? "HS" : "IN"));
                rec.rdata_count = token_count;
                for (int t = 0; t < token_count; t++) rec.rdata[t] = tokens[t];

                uint16_t out_offset = offset;
                if (serialize_dns_record(pkt, max_len, &out_offset, &rec, &comp_ctx, NULL, 0) == 0) {
                    offset = out_offset;
                    uint16_t prcount = (pkt[6] << 8) | pkt[7];
                    prcount++;
                    pkt[6] = prcount >> 8; pkt[7] = prcount & 0xFF;
                } else {
                    fprintf(stderr, "warning: failed to serialize yxrrset prereq rdata: %s\n", qo->prereqs[pi].rdata);
                }
                free(buf);
                continue;
            }

            switch (qo->prereqs[pi].kind) {
                case PREREQ_NXDOMAIN: type = 255; class_val = 254; break; // ANY, NONE
                case PREREQ_YXDOMAIN: type = 255; class_val = 255; break; // ANY, ANY
                case PREREQ_NXRRSET:
                    if (!resolve_qtype(qo->prereqs[pi].type_str, &type)) {
                        fprintf(stderr, "warning: unknown record type '%s' in prereq nxrrset, skipping\n", qo->prereqs[pi].type_str);
                        continue;
                    }
                    class_val = 254; break;
                case PREREQ_YXRRSET:
                    if (!resolve_qtype(qo->prereqs[pi].type_str, &type)) {
                        fprintf(stderr, "warning: unknown record type '%s' in prereq yxrrset, skipping\n", qo->prereqs[pi].type_str);
                        continue;
                    }
                    class_val = 255; break;
                default: continue;
            }

            if (write_dns_name_str(pkt, &offset, name, &comp_ctx, max_len) != 0) {
                fprintf(stderr, "warning: failed to encode prereq name '%s', skipping\n", name);
                continue;
            }
            if ((size_t)offset + 10 > max_len) {
                fprintf(stderr, "warning: packet buffer full, dropping remaining prereqs\n");
                break;
            }
            pkt[offset++] = type >> 8; pkt[offset++] = type & 0xFF;
            pkt[offset++] = class_val >> 8; pkt[offset++] = class_val & 0xFF;
            pkt[offset++] = 0x00; pkt[offset++] = 0x00; pkt[offset++] = 0x00; pkt[offset++] = 0x00; /* TTL 0 */
            pkt[offset++] = 0x00; pkt[offset++] = 0x00; /* RDLEN 0 */

            uint16_t prcount = (pkt[6] << 8) | pkt[7];
            prcount++;
            pkt[6] = prcount >> 8; pkt[7] = prcount & 0xFF;
        }
    }

    if (qo->update_op_count > 0 || has_break(BRK_UPDATE_META_TYPE, NULL, NULL)) {
        compress_ctx_t comp_ctx = {0};
        compress_ctx_init_packet(&comp_ctx);

        for (int oi = 0; oi < qo->update_op_count; oi++) {
            const char *raw = qo->update_ops[oi].raw;

            if (qo->update_ops[oi].kind == UPDATE_OP_ADD) {
                char *buf = strdup(raw);
                char *tokens[32];
                int token_count = 0;
                bool in_quote = false;
                char *p = buf;
                char *tok_start = NULL;
                char *out = buf;

                while (*p && token_count < 32) {
                    if (*p == '"') {
                        in_quote = !in_quote;
                        if (!tok_start) tok_start = out;
                        p++;
                    } else if (*p == ' ' && !in_quote) {
                        if (tok_start) {
                            *out++ = '\0';
                            tokens[token_count++] = tok_start;
                            tok_start = NULL;
                        }
                        p++;
                    } else {
                        if (!tok_start) tok_start = out;
                        if (*p == '\\' && *(p+1) == '"') {
                            p++;
                            *out++ = *p++;
                        } else {
                            *out++ = *p++;
                        }
                    }
                }
                if (tok_start && token_count < 32) {
                    *out = '\0';
                    tokens[token_count++] = tok_start;
                }

                if (token_count >= 3) {
                    int type_idx = 2;
                    char *class_str = (char *)"IN";
                    if (token_count >= 4 && (strcasecmp(tokens[2], "IN") == 0 || strcasecmp(tokens[2], "CH") == 0 ||
                                             strcasecmp(tokens[2], "ANY") == 0 || strcasecmp(tokens[2], "NONE") == 0 ||
                                             strcasecmp(tokens[2], "HS") == 0)) {
                        class_str = tokens[2];
                        type_idx = 3;
                    }
                    if (token_count > type_idx) {
                        uint16_t type_code;
                        if (!resolve_qtype(tokens[type_idx], &type_code)) {
                            fprintf(stderr, "warning: unknown record type '%s' in update-add operation, skipping: %s\n", tokens[type_idx], raw);
                            free(buf);
                            continue;
                        }
                        dns_record_t rec;
                        memset(&rec, 0, sizeof(rec));
                        rec.name = tokens[0];
                        rec.ttl = tokens[1];
                        rec.ttl_value = parse_ttl_value(tokens[1]);
                        rec.type_code = type_code;
                        rec.type = tokens[type_idx];
                        rec.class_str = class_str;
                        rec.rdata_count = token_count - (type_idx + 1);
                        for (int i = 0; i < rec.rdata_count; i++) rec.rdata[i] = tokens[type_idx + 1 + i];

                        uint16_t out_offset = offset;
                        if (serialize_dns_record(pkt, max_len, &out_offset, &rec, &comp_ctx, NULL, 0xFFFFFFFF) == 0) {
                            offset = out_offset;
                            uint16_t upcount = (pkt[8] << 8) | pkt[9];
                            upcount++;
                            pkt[8] = upcount >> 8; pkt[9] = upcount & 0xFF;
                        } else {
                            fprintf(stderr, "Failed to serialize update-add record: %s\n", raw);
                        }
                    } else {
                        fprintf(stderr, "Invalid update-add string format: %s\n", raw);
                    }
                } else {
                    fprintf(stderr, "Invalid update-add string format: %s\n", raw);
                }
                free(buf);

            } else if (qo->update_ops[oi].kind == UPDATE_OP_DEL) { // UPDATE_OP_DEL
                char *buf = strdup(raw);
                char *name = strtok(buf, " ");
                char *type_str = strtok(NULL, " ");
                if (name) {
                    if ((size_t)offset + 10 > max_len) {
                        fprintf(stderr, "warning: packet buffer full, dropping remaining update ops\n");
                        free(buf);
                        break;
                    }
                    uint16_t type = 255; // Default: ANY (255) for all RRsets delete (RFC 2136 §2.5.2)
                    if (type_str) {
                        if (!resolve_qtype(type_str, &type)) {
                            fprintf(stderr, "warning: unknown record type '%s' in update-del operation, skipping: %s\n", type_str, raw);
                            free(buf);
                            continue;
                        }
                    }
                    if (write_dns_name_str(pkt, &offset, name, &comp_ctx, max_len) == 0) {
                        pkt[offset++] = type >> 8; pkt[offset++] = type & 0xFF;
                        pkt[offset++] = 0x00; pkt[offset++] = 255; /* Class ANY */
                        pkt[offset++] = 0x00; pkt[offset++] = 0x00; pkt[offset++] = 0x00; pkt[offset++] = 0x00; /* TTL 0 */
                        pkt[offset++] = 0x00; pkt[offset++] = 0x00; /* RDLEN 0 */
                        uint16_t upcount = (pkt[8] << 8) | pkt[9];
                        upcount++;
                        pkt[8] = upcount >> 8; pkt[9] = upcount & 0xFF;
                    } else {
                        fprintf(stderr, "Failed to serialize update-del name: %s\n", raw);
                    }
                } else {
                    fprintf(stderr, "Invalid update-del string format: %s\n", raw);
                }
                free(buf);
            } else if (qo->update_ops[oi].kind == UPDATE_OP_DEL_EXACT) {
                char *buf = strdup(raw);
                char *tokens[32];
                int token_count = 0;
                bool in_quote = false;
                char *p = buf;
                char *tok_start = NULL;
                char *out = buf;

                while (*p && token_count < 32) {
                    if (*p == '"') {
                        in_quote = !in_quote;
                        if (!tok_start) tok_start = out;
                        p++;
                    } else if (*p == ' ' && !in_quote) {
                        if (tok_start) {
                            *out++ = '\0';
                            tokens[token_count++] = tok_start;
                            tok_start = NULL;
                        }
                        p++;
                    } else {
                        if (!tok_start) tok_start = out;
                        if (*p == '\\' && *(p+1) == '"') {
                            p++;
                            *out++ = *p++;
                        } else {
                            *out++ = *p++;
                        }
                    }
                }
                if (tok_start && token_count < 32) {
                    *out = '\0';
                    tokens[token_count++] = tok_start;
                }

                if (token_count >= 3) {
                    int type_idx = 1;
                    if (token_count >= 3 && (strcasecmp(tokens[1], "NONE") == 0 || strcasecmp(tokens[1], "IN") == 0 ||
                                             strcasecmp(tokens[1], "ANY") == 0 || strcasecmp(tokens[1], "CH") == 0 ||
                                             strcasecmp(tokens[1], "HS") == 0)) {
                        type_idx = 2; // name class type rdata...
                    } else if (token_count >= 3 && isdigit((unsigned char)tokens[1][0])) {
                        if (token_count >= 4 && (strcasecmp(tokens[2], "NONE") == 0 || strcasecmp(tokens[2], "IN") == 0 ||
                                                 strcasecmp(tokens[2], "ANY") == 0 || strcasecmp(tokens[2], "CH") == 0 ||
                                                 strcasecmp(tokens[2], "HS") == 0)) {
                            type_idx = 3; // name ttl class type rdata...
                        } else {
                            type_idx = 2; // name ttl type rdata... (class omitted)
                        }
                    }
                    if (token_count > type_idx) {
                        uint16_t type_code;
                        if (!resolve_qtype(tokens[type_idx], &type_code)) {
                            fprintf(stderr, "warning: unknown record type '%s' in update-del-exact operation, skipping: %s\n", tokens[type_idx], raw);
                            free(buf);
                            continue;
                        }
                        dns_record_t rec;
                        memset(&rec, 0, sizeof(rec));
                        rec.name = tokens[0];
                        rec.ttl = (char *)"0"; // TTL must be 0 for exact match delete
                        rec.type_code = type_code;
                        rec.type = tokens[type_idx];
                        rec.class_str = (char *)"NONE"; // Class NONE for exact match delete
                        rec.rdata_count = token_count - (type_idx + 1);
                        for (int i = 0; i < rec.rdata_count; i++) rec.rdata[i] = tokens[type_idx + 1 + i];

                        uint16_t out_offset = offset;
                        if (serialize_dns_record(pkt, max_len, &out_offset, &rec, &comp_ctx, NULL, 0) == 0) {
                            offset = out_offset;
                            uint16_t upcount = (pkt[8] << 8) | pkt[9];
                            upcount++;
                            pkt[8] = upcount >> 8; pkt[9] = upcount & 0xFF;
                        } else {
                            fprintf(stderr, "Failed to serialize update-del-exact record: %s\n", raw);
                        }
                    } else {
                        fprintf(stderr, "Invalid update-del-exact string format: %s\n", raw);
                    }
                } else {
                    fprintf(stderr, "Invalid update-del-exact string format: %s\n", raw);
                }
                free(buf);
            }
        }

        long meta_type = 0; bool has_meta = false;
        if (has_break(BRK_UPDATE_META_TYPE, &meta_type, &has_meta)) {
            uint16_t fallback_offset = offset;
            if (write_dns_name_str(pkt, &fallback_offset, qname, &comp_ctx, max_len) == 0 && (size_t)fallback_offset + 10 <= max_len) {
                pkt[fallback_offset++] = (uint16_t)meta_type >> 8; pkt[fallback_offset++] = (uint16_t)meta_type & 0xFF;
                pkt[fallback_offset++] = 0x00; pkt[fallback_offset++] = 0x01; /* Class IN */
                pkt[fallback_offset++] = 0x00; pkt[fallback_offset++] = 0x00; pkt[fallback_offset++] = 0x00; pkt[fallback_offset++] = 0x00; /* TTL 0 */
                pkt[fallback_offset++] = 0x00; pkt[fallback_offset++] = 0x00; /* RDLEN 0 */
                offset = fallback_offset;
                uint16_t upcount = (pkt[8] << 8) | pkt[9];
                upcount++;
                pkt[8] = upcount >> 8; pkt[9] = upcount & 0xFF;
            }
        }
    }

    long opt_rdlen_override = 0; bool want_opt_rdlen_break = has_break(BRK_OPT_RDLEN, &opt_rdlen_override, NULL);
    if (qo->want_opt || want_opt_rdlen_break) {
        uint16_t rdlen_field = 0;
        uint16_t before = offset;
        offset = build_opt_record(pkt, max_len, offset, qo, &rdlen_field);
        if (offset > before) {
            uint16_t arcount = (pkt[10] << 8) | pkt[11];
            arcount++;
            pkt[10] = arcount >> 8; pkt[11] = arcount & 0xFF;
            if (want_opt_rdlen_break) {
                pkt[rdlen_field] = (opt_rdlen_override >> 8) & 0xFF;
                pkt[rdlen_field + 1] = opt_rdlen_override & 0xFF;
            }
        }
    }

    long p;
    if (has_break(BRK_QDCOUNT, &p, NULL)) { pkt[4] = (p >> 8) & 0xFF; pkt[5] = p & 0xFF; }
    if (has_break(BRK_ARCOUNT, &p, NULL)) { pkt[10] = (p >> 8) & 0xFF; pkt[11] = p & 0xFF; }
    if (has_break(BRK_OPCODE, &p, NULL))  { pkt[2] = (pkt[2] & 0x87) | ((p & 0x0F) << 3); }
    if (has_break(BRK_QR_BIT, NULL, NULL)) { pkt[2] |= 0x80; }

    return offset;
}

size_t build_and_sign_query(uint8_t *pkt, size_t max_len,
                                   const char *qname, uint16_t qtype,
                                   const query_opts_t *qo,
                                   uint8_t *out_mac, size_t *out_mac_len) {
    size_t pkt_len = build_query_packet(pkt, max_len, qname, qtype, qo);
    if (pkt_len == 0 && !has_break(BRK_TOO_SHORT, NULL, NULL) && !qo->header_only) {
        return 0;
    }
    if (qo->want_tsig) {
        tsig_key_t key = qo->tsig_key;
        key.fuzztime = qo->fuzztime;
        uint8_t dummy_mac[64];
        size_t dummy_mac_len = 0;
        uint8_t *mac_ptr = out_mac ? out_mac : dummy_mac;
        size_t *mac_len_ptr = out_mac_len ? out_mac_len : &dummy_mac_len;
        if (tsig_sign_packet(pkt, &pkt_len, max_len, &key, 0, mac_ptr, mac_len_ptr, NULL, 0, false) != 0) {
            fprintf(stderr, "Error: tsig_sign_packet failed\n");
            return 0;
        }
    }
    if (qo->want_sig0) {
        sig0_key_t key = qo->sig0_key;
        key.fuzztime = qo->fuzztime;
        if (sig0_sign_packet(pkt, &pkt_len, max_len, &key) != 0) {
            fprintf(stderr, "Error: sig0_sign_packet failed\n");
            return 0;
        }
    }
    return pkt_len;
}


void decode_and_print_edns_option(const uint8_t *pkt, size_t p,
                                         uint16_t code, uint16_t olen,
                                         const char *indent,
                                         const display_opts_t *dopt) {
    if (!indent) indent = "";
    bool is_yaml = (indent[0] != ';');

    if (code == 10) { // COOKIE
        if (is_yaml && olen >= 8) {
            char c_cookie[64] = "";
            char s_cookie[128] = "";
            for (int j = 0; j < 8; j++) snprintf(c_cookie + j * 2, 3, "%02x", pkt[p + j]);
            bool c_match = true;
            if (dopt && dopt->has_expected_client_cookie) {
                c_match = (memcmp(dopt->expected_client_cookie, &pkt[p], 8) == 0);
            }
            if (olen > 8) {
                for (int j = 8; j < olen && (j - 8) * 2 < (int)sizeof(s_cookie) - 3; j++) {
                    snprintf(s_cookie + (j - 8) * 2, 3, "%02x", pkt[p + j]);
                }
            }
            printf("%sCOOKIE:\n", indent);
            printf("%s  CLIENT: %s\n", indent, c_cookie);
            if (s_cookie[0] != '\0') {
                printf("%s  SERVER: %s\n", indent, s_cookie);
            }
            if (dopt && dopt->has_expected_client_cookie) {
                printf("%s  STATUS: %s\n", indent, c_match ? "good" : "bad");
            }
        }
        return;
    } else if (code == 3) { // NSID
        printf("%sNSID: ", indent);
        for (uint16_t j = 0; j < olen; j++) printf("%02x", pkt[p + j]);
        printf(" (\"");
        for (uint16_t j = 0; j < olen; j++) {
            unsigned char c = pkt[p + j];
            printf("%c", (c >= 0x20 && c < 0x7f) ? c : '.');
        }
        printf("\")\n");
    } else if (code == 8 && olen >= 4) { // CLIENT-SUBNET
        uint16_t family = (pkt[p] << 8) | pkt[p+1];
        uint8_t src_prefix = pkt[p+2];
        uint8_t scope_prefix = pkt[p+3];
        char abuf[64] = "?";
        uint8_t addr[16] = {0};
        int addr_bytes = olen - 4;
        if (addr_bytes > 16) addr_bytes = 16;
        memcpy(addr, &pkt[p + 4], addr_bytes);
        if (family == 1) inet_ntop(AF_INET, addr, abuf, sizeof(abuf));
        else if (family == 2) inet_ntop(AF_INET6, addr, abuf, sizeof(abuf));
        printf("%sCLIENT-SUBNET: %s/%u/%u\n", indent, abuf, src_prefix, scope_prefix);
    } else if (code == 9) { // EXPIRE
        if (olen >= 4) {
            uint32_t exp_sec = ((uint32_t)pkt[p]<<24)|((uint32_t)pkt[p+1]<<16)|((uint32_t)pkt[p+2]<<8)|pkt[p+3];
            printf("%sEXPIRE: %u (seconds)\n", indent, exp_sec);
        } else {
            printf("%sEXPIRE%s\n", indent, is_yaml ? ":" : "");
        }
    } else if (code == 11) { // KEEPALIVE
        if (olen >= 2) {
            uint16_t to = (pkt[p] << 8) | pkt[p+1];
            printf("%sKEEPALIVE: %u\n", indent, to);
        } else {
            printf("%sKEEPALIVE%s\n", indent, is_yaml ? ":" : "");
        }
    } else if (code == 12) { // PADDING
        printf("%sPADDING: %u octets\n", indent, olen);
    } else if (code == 15) { // EDE
        if (is_yaml && olen >= 2) {
            uint16_t info_code = (pkt[p] << 8) | pkt[p+1];
            const char *msg = get_ede_error_string(info_code);
            printf("%sEDE:\n", indent);
            printf("%s  INFO-CODE: %u (%s)\n", indent, info_code, msg);
            if (olen > 2) {
                char ede_text[512];
                size_t tlen = olen - 2;
                if (tlen >= sizeof(ede_text)) tlen = sizeof(ede_text) - 1;
                memcpy(ede_text, &pkt[p + 2], tlen);
                ede_text[tlen] = '\0';
                char text_esc[512];
                yaml_double_quote_escape(ede_text, text_esc, sizeof(text_esc));
                printf("%s  EXTRA-TEXT: \"%s\"\n", indent, text_esc);
            }
        }
        return;
    } else if (code == 20 || code == 21) { // MQTYPE
        printf("%s%s: ", indent, code == 20 ? "MQTYPE-Query" : "MQTYPE-Response");
        if (olen % 2 != 0) {
            printf("(malformed, length %u is not even)\n", olen);
        } else if (olen == 0) {
            printf("(empty)\n");
        } else {
            for (uint16_t j = 0; j < olen; j += 2) {
                uint16_t mq = (pkt[p + j] << 8) | pkt[p + j + 1];
                char tbuf[16];
                const char *mq_name = format_type_name(mq, tbuf, sizeof(tbuf));
                if (j > 0) printf(" ");
                printf("%s", mq_name);
            }
            printf("\n");
        }
    } else {
        printf("%sOPTION: %u", indent, code);
        if (olen > 0) {
            printf(": ");
            for (uint16_t j = 0; j < olen; j++) printf("%02x ", pkt[p + j]);
        }
        printf("\n");
    }
}


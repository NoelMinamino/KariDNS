#include "dag_trace.h"
#include "dag_output_yaml.h"

static void record_ldnsz_result(const char *server, ssize_t n, const uint8_t *resp, long elapsed_ms, const char *proto) {
    if (n < 12) return;
    server_result_t *sres = alloc_result_row();
    if (!sres) return;
    sres->rcode = resp[3] & 0x0F;
    sres->qdcount = (resp[4] << 8) | resp[5];
    sres->ancount = (resp[6] << 8) | resp[7];
    sres->nscount = (resp[8] << 8) | resp[9];
    sres->arcount = (resp[10] << 8) | resp[11];
    sres->qr = resp[2] & 0x80; sres->aa = resp[2] & 0x04; sres->tc = resp[2] & 0x02; sres->rd = resp[2] & 0x01;
    sres->ra = resp[3] & 0x80; sres->ad = resp[3] & 0x20; sres->cd = resp[3] & 0x10;
    sres->msg_index = 1;
    sres->msg_total = 1;
    size_t to_copy = (size_t)n < sizeof(sres->resp_buf) ? (size_t)n : sizeof(sres->resp_buf);
    memcpy(sres->resp_buf, resp, to_copy);
    sres->resp_len = (ssize_t)to_copy;
    calculate_packet_hashes(resp, n, &sres->semantic_hash, &sres->record_hash);
    snprintf(sres->server_ip, sizeof(sres->server_ip), "%s", server);
    snprintf(sres->proto, sizeof(sres->proto), "%s", proto ? proto : "UDP");
    sres->elapsed_ms = elapsed_ms;
    g_server_count++;
}

/* pkt内のsection_count分のRRをパースし、want_typeに一致するレコードのrdata[0]を
 * out配列(out_cap個まで)に集める。roffは呼び出し元で更新される。 */
static void collect_rrs_by_type(const uint8_t *pkt, size_t pkt_len, size_t *roff,
                                int section_count, uint16_t want_type,
                                char out[][256], int *out_count, int out_cap) {
    for (int i = 0; i < section_count; i++) {
        dns_record_t rec; uint16_t type;
        if (parse_resource_record(pkt, pkt_len, roff, &g_dag_arena, &rec, &type) != 0) break;
        if (type == want_type && *out_count < out_cap && rec.rdata_count > 0) {
            snprintf(out[(*out_count)++], 256, "%s", rec.rdata[0]);
        }
    }
}

static int run_trace_query_impl(const char *qname, const char *server, const char *qtype_s, int port, bool use_tcp, bool force_udp, bool no_hexdump_query, bool no_hexdump_response, const query_opts_t *qo, const char *hex_payload, const display_opts_t *dopt) {
    bool eff_use_tcp = (!force_udp && use_tcp);
    const char *eff_server = server ? server : get_system_resolver();
    display_opts_t trace_dopt = *dopt;
    trace_dopt.show_comments = false;
    trace_dopt.show_question = false;
    trace_dopt.show_stats = false;

    uint8_t *root_qbuf = malloc(65535);
    uint8_t *root_resp = malloc(65535);
    uint8_t *qbuf = malloc(65535);
    uint8_t *resp = malloc(65535);
    if (!root_qbuf || !root_resp || !qbuf || !resp) {
        fprintf(stderr, "Error: Failed to allocate memory for +trace buffers\n");
        free(root_qbuf);
        free(root_resp);
        free(qbuf);
        free(resp);
        return 1;
    }

    char current_qname[256];
    if (strlcpy(current_qname, qname, sizeof(current_qname)) >= sizeof(current_qname)) {
        fprintf(stderr, "Error: qname too long for +trace\n");
        free(root_qbuf);
        free(root_resp);
        free(qbuf);
        free(resp);
        return 1;
    }

    int ret = 0;

    for (int cname_depth = 0; cname_depth <= TRACE_MAX_CNAME_DEPTH; cname_depth++) {
        char target_ips[32][64];
        int target_count = 0;

        query_opts_t root_qo = *qo;
        root_qo.rd_flag = true;
        uint8_t root_req_mac[64];
        size_t root_req_mac_len = 0;
        size_t root_qlen = build_and_sign_query(root_qbuf, 65535, ".", 2 /* NS */, &root_qo, root_req_mac, &root_req_mac_len);
        if (root_qlen == 0) {
            fprintf(stderr, "Error: Failed to construct root query for +trace\n");
            ret = 1;
            goto cleanup;
        }

        if (!no_hexdump_query && !dopt->yaml) {
            printf("Query (%zd bytes):\n", root_qlen);
            hexdump(root_qbuf, root_qlen);
            printf("\n");
        }

        struct timespec start_ts, end_ts;
        clock_gettime(CLOCK_MONOTONIC, &start_ts);
        ssize_t root_n = do_dns_exchange_auto(eff_server, port, &root_qo, root_qbuf, root_qlen, root_resp, 65535, root_qo.timeout_sec, eff_use_tcp);
        clock_gettime(CLOCK_MONOTONIC, &end_ts);

        if (root_n <= 0) {
            if (dopt->yaml) {
                printf("- type: DIG_ERROR\n  message: |\n    no servers could be reached\n");
            } else {
                printf(";; connection timed out; no servers could be reached\n");
            }
            ret = 9;
            goto cleanup;
        }

        int dt_ms = timespec_diff_ms(&start_ts, &end_ts);
        record_ldnsz_result(eff_server, root_n, root_resp, dt_ms, eff_use_tcp ? "TCP" : "UDP");
        if (!no_hexdump_response && !dopt->yaml) {
            printf("Response (%zd bytes):\n", root_n);
            hexdump(root_resp, (size_t)root_n);
            printf("\n");
        }

        if (root_n > 12) {
            if (root_qo.want_tsig) {
                uint8_t dummy_mac[64]; size_t dummy_mac_len = 0;
                int terr = tsig_verify_packet(root_resp, (size_t)root_n, &root_qo.tsig_key, root_req_mac, root_req_mac_len, NULL, 0, false, dummy_mac, &dummy_mac_len);
                if (terr == -1) {
                    printf(";; Couldn't verify signature: expected a TSIG or SIG(0)\n");
                } else if (terr != 0) {
                    printf(";; Couldn't verify signature: tsig verify failure (%d)\n", terr);
                }
                fflush(stdout);
            }
            if (dopt->yaml) {
                print_response_yaml(root_resp, root_n, eff_server, port, eff_use_tcp, dopt);
            } else {
                axfr_state_t dummy_axfr = {0};
                print_response(root_resp, root_n, &dummy_axfr, &trace_dopt);
                int dt_ms_root = timespec_diff_ms(&start_ts, &end_ts);
                printf(";; Received %zd bytes from %s#%d in %d ms\n\n", root_n, eff_server, port, dt_ms_root);
            }

            size_t offset = 12;
            int r_qd = (root_resp[4] << 8) | root_resp[5];
            int r_an = (root_resp[6] << 8) | root_resp[7];
            int r_ns = (root_resp[8] << 8) | root_resp[9];
            int r_ar = (root_resp[10] << 8) | root_resp[11];
            for (int i = 0; i < r_qd; i++) {
                char *d;
                if (expand_wire_name(root_resp, root_n, offset, &offset, &g_dag_arena, &d) != 0) break;
                offset += 4;
            }

            char rns_names[32][256];
            int rns_count = 0;
            collect_rrs_by_type(root_resp, root_n, &offset, r_an, 2 /* NS */, rns_names, &rns_count, 32);
            collect_rrs_by_type(root_resp, root_n, &offset, r_ns, 2 /* NS */, rns_names, &rns_count, 32);
            for (int i = 0; i < r_ar; i++) {
                dns_record_t rec; uint16_t type;
                if (parse_resource_record(root_resp, root_n, &offset, &g_dag_arena, &rec, &type) != 0) break;
                bool want = false;
                if (type == 1 && (root_qo.pref_family == AF_UNSPEC || root_qo.pref_family == AF_INET)) want = true;
                if (type == 28 && (root_qo.pref_family == AF_UNSPEC || root_qo.pref_family == AF_INET6)) want = true;
                if (want && rec.rdata_count > 0) {
                    for (int j = 0; j < rns_count; j++) {
                        if (strcasecmp(rec.name, rns_names[j]) == 0 && target_count < 32) {
                            snprintf(target_ips[target_count++], sizeof(target_ips[0]), "%s", rec.rdata[0]);
                        }
                    }
                }
            }

            if (target_count == 0 && rns_count > 0) {
                query_opts_t resolve_qo = root_qo;
                resolve_qo.rd_flag = true;
                for (int j = 0; j < rns_count && target_count < 32; j++) {
                    if (root_qo.pref_family == AF_UNSPEC || root_qo.pref_family == AF_INET) {
                        uint8_t res_qbuf[512];
                        uint8_t res_req_mac[64];
                        size_t res_req_mac_len = 0;
                        size_t res_qlen = build_and_sign_query(res_qbuf, sizeof(res_qbuf), rns_names[j], 1 /* A */, &resolve_qo, res_req_mac, &res_req_mac_len);
                        uint8_t res_resp[4096];
                        ssize_t res_n = do_dns_exchange_auto(eff_server, port, &resolve_qo, res_qbuf, res_qlen, res_resp, sizeof(res_resp), resolve_qo.timeout_sec, eff_use_tcp);
                        if (res_n > 12) {
                            int qd = (res_resp[4] << 8) | res_resp[5];
                            int an = (res_resp[6] << 8) | res_resp[7];
                            size_t roff = 12;
                            for (int k = 0; k < qd; k++) {
                                char *d;
                                if (expand_wire_name(res_resp, res_n, roff, &roff, &g_dag_arena, &d) != 0) break;
                                roff += 4;
                            }
                            for (int k = 0; k < an; k++) {
                                dns_record_t rec; uint16_t type;
                                if (parse_resource_record(res_resp, res_n, &roff, &g_dag_arena, &rec, &type) != 0) break;
                                if (type == 1 && rec.rdata_count > 0 && target_count < 32) {
                                    snprintf(target_ips[target_count++], sizeof(target_ips[0]), "%s", rec.rdata[0]);
                                }
                            }
                        }
                    }
                    if (target_count < 32 && (root_qo.pref_family == AF_UNSPEC || root_qo.pref_family == AF_INET6)) {
                        uint8_t res_qbuf[512];
                        uint8_t res_req_mac[64];
                        size_t res_req_mac_len = 0;
                        size_t res_qlen = build_and_sign_query(res_qbuf, sizeof(res_qbuf), rns_names[j], 28 /* AAAA */, &resolve_qo, res_req_mac, &res_req_mac_len);
                        uint8_t res_resp[4096];
                        ssize_t res_n = do_dns_exchange_auto(eff_server, port, &resolve_qo, res_qbuf, res_qlen, res_resp, sizeof(res_resp), resolve_qo.timeout_sec, eff_use_tcp);
                        if (res_n > 12) {
                            int qd = (res_resp[4] << 8) | res_resp[5];
                            int an = (res_resp[6] << 8) | res_resp[7];
                            size_t roff = 12;
                            for (int k = 0; k < qd; k++) {
                                char *d;
                                if (expand_wire_name(res_resp, res_n, roff, &roff, &g_dag_arena, &d) != 0) break;
                                roff += 4;
                            }
                            for (int k = 0; k < an; k++) {
                                dns_record_t rec; uint16_t type;
                                if (parse_resource_record(res_resp, res_n, &roff, &g_dag_arena, &rec, &type) != 0) break;
                                if (type == 28 && rec.rdata_count > 0 && target_count < 32) {
                                    snprintf(target_ips[target_count++], sizeof(target_ips[0]), "%s", rec.rdata[0]);
                                }
                            }
                        }
                    }
                }
            }
        }

        if (target_count == 0) {
            ret = 0;
            goto cleanup;
        }

        query_opts_t hop_qo = *qo;
        hop_qo.rd_flag = false;
        bool follow_cname = false;

        for (int hop = 1; hop < 32 && target_count > 0; hop++) {
            reset_dag_arena();
            size_t qlen = 0;
            uint8_t hop_req_mac[64];
            size_t hop_req_mac_len = 0;
            if (hex_payload) {
                qlen = parse_hex_string(hex_payload, qbuf, 65535);
                if (qlen == 0 || qlen > 65535) {
                    fprintf(stderr, "Error: Invalid, empty, or oversized hex payload (max 65535 bytes)\n");
                    ret = 1;
                    goto cleanup;
                }
            } else {
                int qtype_val = parse_qtype(qtype_s);
                if (qtype_val < 0) {
                    ret = 1;
                    goto cleanup;
                }
                qlen = build_and_sign_query(qbuf, 65535, current_qname, (uint16_t)qtype_val, &hop_qo, hop_req_mac, &hop_req_mac_len);
                if (qlen == 0) break;
            }

            ssize_t n = -1;
            int active_target_idx = 0;

            for (int ti = 0; ti < target_count; ti++) {
                if (!no_hexdump_query && !dopt->yaml) {
                    printf("Query (%zd bytes):\n", qlen);
                    hexdump(qbuf, qlen);
                    printf("\n");
                }
                clock_gettime(CLOCK_MONOTONIC, &start_ts);
                n = do_dns_exchange_auto(target_ips[ti], port, &hop_qo, qbuf, qlen, resp, 65535, hop_qo.timeout_sec, eff_use_tcp);
                clock_gettime(CLOCK_MONOTONIC, &end_ts);
                if (n > 0) {
                    active_target_idx = ti;
                    break;
                }
                if (dopt->yaml) {
                    printf("- type: DIG_ERROR\n  message: |\n    no servers could be reached\n");
                } else {
                    printf(";; connection to %s#%d timed out; trying next server...\n", target_ips[ti], port);
                }
            }

            if (n <= 0) {
                if (dopt->yaml) {
                    printf("- type: DIG_ERROR\n  message: |\n    no servers could be reached\n");
                } else {
                    printf(";; no servers could be reached for hop %d\n", hop);
                }
                ret = 9;
                goto cleanup;
            }

            int dt_ms_hop = timespec_diff_ms(&start_ts, &end_ts);
            record_ldnsz_result(target_ips[active_target_idx], n, resp, dt_ms_hop, eff_use_tcp ? "TCP" : "UDP");

            if (!no_hexdump_response && !dopt->yaml) {
                printf("Response (%zd bytes):\n", n);
                hexdump(resp, (size_t)n);
                printf("\n");
            }

            if (n > 12 && hop_qo.want_tsig) {
                uint8_t dummy_mac[64]; size_t dummy_mac_len = 0;
                int terr = tsig_verify_packet(resp, (size_t)n, &hop_qo.tsig_key, hop_req_mac, hop_req_mac_len, NULL, 0, false, dummy_mac, &dummy_mac_len);
                if (terr == -1) {
                    printf(";; Couldn't verify signature: expected a TSIG or SIG(0)\n");
                } else if (terr != 0) {
                    printf(";; Couldn't verify signature: tsig verify failure (%d)\n", terr);
                }
                fflush(stdout);
            }

            if (dopt->yaml) {
                print_response_yaml(resp, n, target_ips[active_target_idx], port, eff_use_tcp, dopt);
            } else {
                axfr_state_t dummy_axfr = {0};
                print_response(resp, n, &dummy_axfr, &trace_dopt);
                printf(";; Received %zd bytes from %s#%d in %d ms\n\n", n, target_ips[active_target_idx], port, dt_ms_hop);
            }

            if (n < 12) break;
            int flags = (resp[2] << 8) | resp[3];
            int ancount = (resp[6] << 8) | resp[7];
            int nscount = (resp[8] << 8) | resp[9];
            int arcount = (resp[10] << 8) | resp[11];
            int rcode = flags & 0x0F;

            if (ancount > 0 || rcode != 0) {
                if (rcode == 0 && ancount > 0) {
                    char cname_target[256] = "";
                    size_t an_off = 12;
                    int qdcount = (resp[4] << 8) | resp[5];
                    for (int i = 0; i < qdcount; i++) {
                        char *dummy;
                        if (expand_wire_name(resp, n, an_off, &an_off, &g_dag_arena, &dummy) != 0) break;
                        an_off += 4;
                    }
                    for (int i = 0; i < ancount; i++) {
                        dns_record_t rec; uint16_t rtype;
                        if (parse_resource_record(resp, n, &an_off, &g_dag_arena, &rec, &rtype) != 0) break;
                        if (rtype == 5 /* CNAME */ && rec.rdata_count > 0) {
                            snprintf(cname_target, sizeof(cname_target), "%s", rec.rdata[0]);
                        }
                    }
                    if (cname_target[0] != '\0' && cname_depth < TRACE_MAX_CNAME_DEPTH) {
                        strlcpy(current_qname, cname_target, sizeof(current_qname));
                        follow_cname = true;
                    }
                }
                break;
            }

            if (nscount == 0) break;

            size_t offset = 12;
            int qdcount = (resp[4] << 8) | resp[5];
            for (int i = 0; i < qdcount; i++) {
                char *dummy;
                if (expand_wire_name(resp, n, offset, &offset, &g_dag_arena, &dummy) != 0) break;
                offset += 4;
            }

            char ns_names[16][256];
            int ns_count = 0;
            collect_rrs_by_type(resp, n, &offset, nscount, 2 /* NS */, ns_names, &ns_count, 16);

            int new_target_count = 0;
            char new_target_ips[16][64];
            for (int i = 0; i < arcount; i++) {
                dns_record_t rec; uint16_t type;
                if (parse_resource_record(resp, n, &offset, &g_dag_arena, &rec, &type) != 0) break;
                bool want = false;
                if (type == 1 && (hop_qo.pref_family == AF_UNSPEC || hop_qo.pref_family == AF_INET)) want = true;
                if (type == 28 && (hop_qo.pref_family == AF_UNSPEC || hop_qo.pref_family == AF_INET6)) want = true;
                if (want && rec.rdata_count > 0) {
                    bool match = false;
                    for (int j=0; j<ns_count; j++) {
                        if (strcasecmp(rec.name, ns_names[j]) == 0) { match = true; break; }
                    }
                    if (match && new_target_count < 16) {
                        snprintf(new_target_ips[new_target_count++], sizeof(new_target_ips[0]), "%s", rec.rdata[0]);
                    }
                }
            }

            if (new_target_count == 0 && ns_count > 0) {
                query_opts_t resolve_qo = hop_qo;
                resolve_qo.rd_flag = true;
                for (int j = 0; j < ns_count && new_target_count < 16; j++) {
                    if (hop_qo.pref_family == AF_UNSPEC || hop_qo.pref_family == AF_INET) {
                        uint8_t res_qbuf[512];
                        uint8_t res_req_mac[64];
                        size_t res_req_mac_len = 0;
                        size_t res_qlen = build_and_sign_query(res_qbuf, sizeof(res_qbuf), ns_names[j], 1 /* A */, &resolve_qo, res_req_mac, &res_req_mac_len);
                        uint8_t res_resp[4096];
                        ssize_t res_n = do_dns_exchange_auto(eff_server, port, &resolve_qo, res_qbuf, res_qlen, res_resp, sizeof(res_resp), resolve_qo.timeout_sec, eff_use_tcp);
                        if (res_n > 12) {
                            int r_qd = (res_resp[4] << 8) | res_resp[5];
                            int r_an = (res_resp[6] << 8) | res_resp[7];
                            size_t roff = 12;
                            for (int k = 0; k < r_qd; k++) {
                                char *d;
                                if (expand_wire_name(res_resp, res_n, roff, &roff, &g_dag_arena, &d) != 0) break;
                                roff += 4;
                            }
                            for (int k = 0; k < r_an; k++) {
                                dns_record_t rec; uint16_t type;
                                if (parse_resource_record(res_resp, res_n, &roff, &g_dag_arena, &rec, &type) != 0) break;
                                if (type == 1 && rec.rdata_count > 0 && new_target_count < 16) {
                                    snprintf(new_target_ips[new_target_count++], sizeof(new_target_ips[0]), "%s", rec.rdata[0]);
                                }
                            }
                        }
                    }
                    if (new_target_count < 16 && (hop_qo.pref_family == AF_UNSPEC || hop_qo.pref_family == AF_INET6)) {
                        uint8_t res_qbuf[512];
                        uint8_t res_req_mac[64];
                        size_t res_req_mac_len = 0;
                        size_t res_qlen = build_and_sign_query(res_qbuf, sizeof(res_qbuf), ns_names[j], 28 /* AAAA */, &resolve_qo, res_req_mac, &res_req_mac_len);
                        uint8_t res_resp[4096];
                        ssize_t res_n = do_dns_exchange_auto(eff_server, port, &resolve_qo, res_qbuf, res_qlen, res_resp, sizeof(res_resp), resolve_qo.timeout_sec, eff_use_tcp);
                        if (res_n > 12) {
                            int r_qd = (res_resp[4] << 8) | res_resp[5];
                            int r_an = (res_resp[6] << 8) | res_resp[7];
                            size_t roff = 12;
                            for (int k = 0; k < r_qd; k++) {
                                char *d;
                                if (expand_wire_name(res_resp, res_n, roff, &roff, &g_dag_arena, &d) != 0) break;
                                roff += 4;
                            }
                            for (int k = 0; k < r_an; k++) {
                                dns_record_t rec; uint16_t type;
                                if (parse_resource_record(res_resp, res_n, &roff, &g_dag_arena, &rec, &type) != 0) break;
                                if (type == 28 && rec.rdata_count > 0 && new_target_count < 16) {
                                    snprintf(new_target_ips[new_target_count++], sizeof(new_target_ips[0]), "%s", rec.rdata[0]);
                                }
                            }
                        }
                    }
                }
            }

            if (new_target_count == 0) {
                if (!dopt->yaml) {
                    printf(";; No glue found for next hop, stopping trace.\n");
                }
                break;
            }

            target_count = new_target_count;
            _Static_assert(sizeof(target_ips[0]) == sizeof(new_target_ips[0]), "buffer size mismatch");
            for(int i=0; i<target_count; i++) {
                if (strlcpy(target_ips[i], new_target_ips[i], sizeof(target_ips[i])) >= sizeof(target_ips[i])) {
                    fprintf(stderr, "warning: target IP truncated\n");
                }
            }
        } // end hop loop

        if (follow_cname) {
            continue;
        }
        break;
    } // end cname_depth loop

cleanup:
    free(root_qbuf);
    free(root_resp);
    free(qbuf);
    free(resp);
    return ret;
}

int run_trace_query(const char *qname, const char *server, const char *qtype_s, int port, bool use_tcp, bool force_udp, bool no_hexdump_query, bool no_hexdump_response, const query_opts_t *qo, const char *hex_payload, const display_opts_t *dopt) {
    return run_trace_query_impl(qname, server, qtype_s, port, use_tcp, force_udp, no_hexdump_query, no_hexdump_response, qo, hex_payload, dopt);
}

int run_nssearch(const char *qname, const char *server, int port, bool use_tcp, bool force_udp, bool no_hexdump_query, bool no_hexdump_response, query_opts_t qo, const char *hex_payload, const display_opts_t *dopt) {
    (void)dopt;
    bool eff_use_tcp = (!force_udp && use_tcp);
    const char *eff_server = server ? server : get_system_resolver();
    query_opts_t ns_qo = qo;
    ns_qo.rd_flag = true;
    uint8_t qbuf[65535];
    uint8_t ns_req_mac[64];
    size_t ns_req_mac_len = 0;
    size_t qlen = build_and_sign_query(qbuf, sizeof(qbuf), qname, 2 /* NS */, &ns_qo, ns_req_mac, &ns_req_mac_len);
    if (!no_hexdump_query) {
        printf("Query (%zd bytes):\n", qlen);
        hexdump(qbuf, qlen);
        printf("\n");
    }
    uint8_t resp[65535];
    struct timespec start_ts, end_ts;
    clock_gettime(CLOCK_MONOTONIC, &start_ts);
    ssize_t n = do_dns_exchange_auto(eff_server, port, &ns_qo, qbuf, qlen, resp, sizeof(resp), ns_qo.timeout_sec, eff_use_tcp);
    clock_gettime(CLOCK_MONOTONIC, &end_ts);
    if (n > 0) {
        int dt_ms = timespec_diff_ms(&start_ts, &end_ts);
        record_ldnsz_result(eff_server, n, resp, dt_ms, eff_use_tcp ? "TCP" : "UDP");
        if (!no_hexdump_response) {
            printf("Response (%zd bytes):\n", n);
            hexdump(resp, (size_t)n);
            printf("\n");
        }
    }
    if (n <= 0) {
        printf(";; connection timed out; no servers could be reached\n");
        return 9;
    }
    
    if (n < 12) return 1;

    if (ns_qo.want_tsig) {
        uint8_t dummy_mac[64]; size_t dummy_mac_len = 0;
        int terr = tsig_verify_packet(resp, (size_t)n, &ns_qo.tsig_key, ns_req_mac, ns_req_mac_len, NULL, 0, false, dummy_mac, &dummy_mac_len);
        if (terr == -1) {
            printf(";; Couldn't verify signature: expected a TSIG or SIG(0)\n");
        } else if (terr != 0) {
            printf(";; Couldn't verify signature: tsig verify failure (%d)\n", terr);
        }
        fflush(stdout);
    }
    int qdcount = (resp[4] << 8) | resp[5];
    int ancount = (resp[6] << 8) | resp[7];
    int nscount = (resp[8] << 8) | resp[9];
    int arcount = (resp[10] << 8) | resp[11];
    
    size_t offset = 12;
    for (int i = 0; i < qdcount; i++) {
        char *dummy;
        if (expand_wire_name(resp, n, offset, &offset, &g_dag_arena, &dummy) != 0) return 1;
        offset += 4;
    }
    
    char ns_names[32][256];
    int ns_count = 0;
    int an_parsed = 0;
    for (; an_parsed < ancount; an_parsed++) {
        dns_record_t rec; uint16_t type;
        if (parse_resource_record(resp, n, &offset, &g_dag_arena, &rec, &type) != 0) break;
        if (type == 2 && ns_count < 32 && rec.rdata_count > 0) {
            snprintf(ns_names[ns_count++], sizeof(ns_names[0]), "%s", rec.rdata[0]);
        }
    }
    int ns_parsed = 0;
    for (; ns_parsed < nscount; ns_parsed++) {
        dns_record_t rec; uint16_t type;
        if (parse_resource_record(resp, n, &offset, &g_dag_arena, &rec, &type) != 0) break;
        if (type == 2 && ns_count < 32 && rec.rdata_count > 0) {
            snprintf(ns_names[ns_count++], sizeof(ns_names[0]), "%s", rec.rdata[0]);
        }
    }

    if (ns_count == 0) {
        printf(";; no NS records found for %s\n", qname);
        return 1;
    }

    struct { char ns_name[256]; char ip[64]; } all_ns_ips[128];
    int all_ns_count = 0;
    bool ns_has_glue[32] = {false};

    // Scan remaining records up to ADDITIONAL section
    for (int i = an_parsed; i < ancount; i++) {
        dns_record_t rec; uint16_t type;
        if (parse_resource_record(resp, n, &offset, &g_dag_arena, &rec, &type) != 0) break;
    }
    for (int i = ns_parsed; i < nscount; i++) {
        dns_record_t rec; uint16_t type;
        if (parse_resource_record(resp, n, &offset, &g_dag_arena, &rec, &type) != 0) break;
    }

    // Scan ADDITIONAL section for glue A/AAAA records (if +glue is active)
    if (qo.use_glue) {
        for (int i = 0; i < arcount; i++) {
            dns_record_t rec; uint16_t type;
            if (parse_resource_record(resp, n, &offset, &g_dag_arena, &rec, &type) != 0) break;
            bool want = false;
            if (type == 1 && (qo.pref_family == AF_UNSPEC || qo.pref_family == AF_INET)) want = true;
            if (type == 28 && (qo.pref_family == AF_UNSPEC || qo.pref_family == AF_INET6)) want = true;
            if (want && rec.rdata_count > 0) {
                for (int j = 0; j < ns_count; j++) {
                    if (strcasecmp(rec.name, ns_names[j]) == 0) {
                        ns_has_glue[j] = true;
                        bool duplicate = false;
                        for (int d = 0; d < all_ns_count; d++) {
                            if (strcmp(all_ns_ips[d].ip, rec.rdata[0]) == 0) { duplicate = true; break; }
                        }
                        if (!duplicate && all_ns_count < 128) {
                            snprintf(all_ns_ips[all_ns_count].ns_name, sizeof(all_ns_ips[all_ns_count].ns_name), "%s", ns_names[j]);
                            snprintf(all_ns_ips[all_ns_count].ip, sizeof(all_ns_ips[all_ns_count].ip), "%s", rec.rdata[0]);
                            all_ns_count++;
                        }
                    }
                }
            }
        }
    }

    // Resolve out-of-bailiwick NS names without glue using getaddrinfo
    for (int j = 0; j < ns_count; j++) {
        if (ns_has_glue[j]) continue;
        char clean_name[256];
        snprintf(clean_name, sizeof(clean_name), "%s", ns_names[j]);
        size_t c_len = strlen(clean_name);
        if (c_len > 1 && clean_name[c_len - 1] == '.') {
            clean_name[c_len - 1] = '\0';
        }

        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = qo.pref_family;
        hints.ai_socktype = SOCK_DGRAM;

        if (getaddrinfo(clean_name, NULL, &hints, &res) == 0 && res != NULL) {
            for (struct addrinfo *p = res; p != NULL && all_ns_count < 128; p = p->ai_next) {
                char ip_str[64];
                if (p->ai_family == AF_INET) {
                    struct sockaddr_in *sin = (struct sockaddr_in *)p->ai_addr;
                    inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));
                } else if (p->ai_family == AF_INET6) {
                    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)p->ai_addr;
                    inet_ntop(AF_INET6, &sin6->sin6_addr, ip_str, sizeof(ip_str));
                } else {
                    continue;
                }
                bool duplicate = false;
                for (int d = 0; d < all_ns_count; d++) {
                    if (strcmp(all_ns_ips[d].ip, ip_str) == 0) { duplicate = true; break; }
                }
                if (!duplicate) {
                    snprintf(all_ns_ips[all_ns_count].ns_name, sizeof(all_ns_ips[all_ns_count].ns_name), "%s", ns_names[j]);
                    snprintf(all_ns_ips[all_ns_count].ip, sizeof(all_ns_ips[all_ns_count].ip), "%s", ip_str);
                    all_ns_count++;
                }
            }
            freeaddrinfo(res);
        } else {
            fprintf(stderr, "couldn't get address for '%s': failure\n", clean_name);
        }
    }

    if (all_ns_count == 0) {
        char clean_first[256];
        snprintf(clean_first, sizeof(clean_first), "%s", ns_names[0]);
        size_t c_len = strlen(clean_first);
        if (c_len > 0 && clean_first[c_len - 1] == '.') clean_first[c_len - 1] = '\0';
        fprintf(stderr, "dig: couldn't get address for '%s': no more\n", clean_first);
        return 9;
    }

    for (int k = 0; k < all_ns_count; k++) {
        size_t slen = 0;
        uint8_t soa_req_mac[64];
        size_t soa_req_mac_len = 0;
        if (hex_payload) {
            slen = parse_hex_string(hex_payload, qbuf, sizeof(qbuf));
            if (slen == 0 || slen > sizeof(qbuf)) {
                fprintf(stderr, "Error: Invalid, empty, or oversized hex payload (max %zu bytes)\n", sizeof(qbuf));
                return 1;
            }
        } else {
            slen = build_and_sign_query(qbuf, sizeof(qbuf), qname, 6 /* SOA */, &qo, soa_req_mac, &soa_req_mac_len);
        }
        if (!no_hexdump_query) {
            printf("Query (%zd bytes):\n", slen);
            hexdump(qbuf, slen);
            printf("\n");
        }
        clock_gettime(CLOCK_MONOTONIC, &start_ts);
        ssize_t sn = do_dns_exchange_auto(all_ns_ips[k].ip, port, &qo, qbuf, slen, resp, sizeof(resp), qo.timeout_sec, eff_use_tcp);
        clock_gettime(CLOCK_MONOTONIC, &end_ts);
        int dt_ms = 0;
        if (sn > 0) {
            dt_ms = timespec_diff_ms(&start_ts, &end_ts);
            record_ldnsz_result(all_ns_ips[k].ip, sn, resp, dt_ms, eff_use_tcp ? "TCP" : "UDP");
            if (!no_hexdump_response) {
                printf("Response (%zd bytes):\n", sn);
                hexdump(resp, (size_t)sn);
                printf("\n");
            }
        }
        if (sn > 12) {
            if (qo.want_tsig) {
                uint8_t dummy_mac[64]; size_t dummy_mac_len = 0;
                int terr = tsig_verify_packet(resp, (size_t)sn, &qo.tsig_key, soa_req_mac, soa_req_mac_len, NULL, 0, false, dummy_mac, &dummy_mac_len);
                if (terr == -1) {
                    printf(";; Couldn't verify signature: expected a TSIG or SIG(0)\n");
                } else if (terr != 0) {
                    printf(";; Couldn't verify signature: tsig verify failure (%d)\n", terr);
                }
                fflush(stdout);
            }
            int sancount = (resp[6] << 8) | resp[7];
            size_t soff = 12;
            int sqdcount = (resp[4] << 8) | resp[5];
            for (int i = 0; i < sqdcount; i++) {
                char *d;
                if (expand_wire_name(resp, sn, soff, &soff, &g_dag_arena, &d) != 0) break;
                soff += 4;
            }
            for (int i=0; i<sancount; i++) {
                dns_record_t rec; uint16_t type;
                if (parse_resource_record(resp, sn, &soff, &g_dag_arena, &rec, &type) != 0) break;
                if (type == 6 && rec.rdata_count >= 7) {
                    printf("SOA %s %s %s %s %s %s %s from server %s in %d ms\n",
                           rec.rdata[0], rec.rdata[1], rec.rdata[2], rec.rdata[3], rec.rdata[4], rec.rdata[5], rec.rdata[6],
                           all_ns_ips[k].ip, dt_ms);
                    break;
                }
            }
        } else {
            printf(";; connection timed out; no servers could be reached\n");
        }
    }
    return 0;
}

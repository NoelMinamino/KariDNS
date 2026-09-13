#include "dag_tsig_client.h"

void parse_tsig_str(char *tsig_str, query_opts_t *qo) {
    qo->want_tsig = true;
    char *colon1 = strchr(tsig_str, ':');
    if (colon1) {
        char *colon2 = strchr(colon1 + 1, ':');
        char *alg, *name, *secret_b64;
        if (colon2) {
            *colon1 = '\0'; *colon2 = '\0';
            alg = strdup(tsig_str); name = strdup(colon1 + 1); secret_b64 = colon2 + 1;
        } else {
            *colon1 = '\0';
            alg = strdup("hmac-sha256"); name = strdup(tsig_str); secret_b64 = colon1 + 1;
        }
        if (qo->tsig_key.algorithm) free((void *)qo->tsig_key.algorithm);
        if (qo->tsig_key.name) free((void *)qo->tsig_key.name);
        qo->tsig_key.algorithm = alg;
        qo->tsig_key.name = name;
        int b64_len = strlen(secret_b64);
        int pad = 0;
        if (b64_len > 0 && secret_b64[b64_len - 1] == '=') pad++;
        if (b64_len > 1 && secret_b64[b64_len - 2] == '=') pad++;
        size_t decoded_upper_bound = ((b64_len + 3) / 4) * 3;
        if (b64_len == 0 || decoded_upper_bound > sizeof(qo->tsig_key.secret_decoded)) {
            fprintf(stderr, "warning: tsig secret base64 too long or empty\n");
            qo->want_tsig = false;
            return;
        }
        int dec_len = EVP_DecodeBlock(qo->tsig_key.secret_decoded, (const unsigned char *)secret_b64, b64_len);
        if (dec_len > 0 && dec_len >= pad) {
            qo->tsig_key.secret_decoded_len = (size_t)(dec_len - pad);
        } else {
            fprintf(stderr, "warning: invalid tsig secret base64\n");
            qo->want_tsig = false;
        }
    } else {
        fprintf(stderr, "warning: invalid tsig format (expected [alg:]name:key)\n");
        qo->want_tsig = false;
    }
}

void parse_tsig_keyfile(const char *path, query_opts_t *qo) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "warning: could not open TSIG key file '%s': %s\n", path, strerror(errno));
        return;
    }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    #define KARIDNS_MAX_TSIG_KEYFILE_SIZE (64 * 1024)
    if (size < 0 || size > KARIDNS_MAX_TSIG_KEYFILE_SIZE) {
        fprintf(stderr, "warning: TSIG key file '%s' is not a regular seekable file or exceeds size limit\n", path);
        fclose(f);
        return;
    }
    
    char *buf = malloc((size_t)size + 1);
    if (!buf) { fclose(f); return; }
    size_t n = fread(buf, 1, (size_t)size, f);
    buf[n] = '\0';
    fclose(f);
    
    char name[128] = {0}, algo[128] = {0}, secret[256] = {0};
    
    char *p = strstr(buf, "key ");
    if (p) {
        p += 4;
        while (*p == ' ' || *p == '\t' || *p == '\n') p++;
        if (*p == '"') {
            p++;
            char *end = strchr(p, '"');
            if (end && (long)(end - p) < (long)sizeof(name)) {
                memcpy(name, p, end - p);
                name[end - p] = '\0';
            }
        } else {
            sscanf(p, "%127s", name);
        }
    }
    
    p = strstr(buf, "algorithm ");
    if (p) {
        p += 10;
        while (*p == ' ' || *p == '\t' || *p == '\n') p++;
        if (*p == '"') p++;
        char *end = p;
        while (*end && *end != ';' && *end != '"' && *end != ' ' && *end != '\n') end++;
        if ((long)(end - p) < (long)sizeof(algo)) {
            memcpy(algo, p, end - p);
            algo[end - p] = '\0';
        }
    }
    
    p = strstr(buf, "secret ");
    if (p) {
        p += 7;
        while (*p == ' ' || *p == '\t' || *p == '\n') p++;
        if (*p == '"') {
            p++;
            char *end = strchr(p, '"');
            if (end && (long)(end - p) < (long)sizeof(secret)) {
                memcpy(secret, p, end - p);
                secret[end - p] = '\0';
            }
        } else {
            char *end = p;
            while (*end && *end != ';' && *end != ' ' && *end != '\t' && *end != '\n') end++;
            if ((long)(end - p) < (long)sizeof(secret)) {
                memcpy(secret, p, end - p);
                secret[end - p] = '\0';
            }
        }
    }
    
    free(buf);
    
    if (name[0] && secret[0]) {
        if (!algo[0]) {
            if (strlcpy(algo, "hmac-sha256", sizeof(algo)) >= sizeof(algo)) {
                fprintf(stderr, "warning: algorithm name truncated\n");
            }
        }
        size_t combined_len = strlen(name) + strlen(secret) + strlen(algo) + 3;
        char *combined_copy = arena_alloc(&g_dag_arena, combined_len);
        if (!combined_copy) {
            fprintf(stderr, "error: out of memory for TSIG key string\n");
            return;
        }
        snprintf(combined_copy, combined_len, "%s:%s:%s", algo, name, secret);
        parse_tsig_str(combined_copy, qo);
    } else {
        fprintf(stderr, "warning: failed to parse TSIG key from '%s'\n", path);
    }
}

static int b64_char_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static size_t b64_decode_clean(const char *in, uint8_t *out, size_t max_out) {
    size_t out_len = 0;
    uint32_t buf = 0;
    int bits = 0;
    for (; in && *in; in++) {
        if (*in == '=') break;
        int val = b64_char_val(*in);
        if (val < 0) continue;
        buf = (buf << 6) | (uint32_t)val;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (out_len < max_out) {
                out[out_len++] = (uint8_t)((buf >> bits) & 0xFF);
            }
        }
    }
    return out_len;
}

static bool extract_bind_field(const char *file_content, const char *field_name, char *out_val, size_t max_out) {
    if (!file_content || !field_name || !out_val || max_out == 0) return false;
    out_val[0] = '\0';
    size_t fn_len = strlen(field_name);
    const char *p = file_content;
    while (*p) {
        while (*p == ' ' || *p == '\t') p++;
        if (strncmp(p, field_name, fn_len) == 0 && (p[fn_len] == ':' || p[fn_len] == ' ' || p[fn_len] == '\t')) {
            p += fn_len;
            while (*p == ' ' || *p == '\t' || *p == ':') p++;
            size_t out_len = 0;
            while (*p) {
                if (*p == '\r' || *p == '\n') {
                    const char *next_line = p;
                    while (*next_line == '\r' || *next_line == '\n') next_line++;
                    if (*next_line == '\0') break;
                    const char *check = next_line;
                    while (isalnum((unsigned char)*check) || *check == '-') check++;
                    if (check > next_line && *check == ':') {
                        break;
                    }
                    p = next_line;
                    continue;
                }
                if (!isspace((unsigned char)*p)) {
                    if (out_len + 1 < max_out) {
                        out_val[out_len++] = *p;
                    }
                }
                p++;
            }
            out_val[out_len] = '\0';
            return (out_len > 0);
        }
        while (*p && *p != '\n') p++;
        if (*p == '\n') p++;
    }
    return false;
}

static void extract_bind_key_info_from_filename(const char *path, char *out_name, size_t name_size, uint8_t *out_alg, uint16_t *out_tag) {
    if (!path) return;
    const char *slash = strrchr(path, '/');
#ifdef _WIN32
    const char *bslash = strrchr(path, '\\');
    if (bslash && (!slash || bslash > slash)) slash = bslash;
#endif
    const char *base = slash ? slash + 1 : path;
    if (base[0] != 'K') return;

    const char *p = base + 1;
    const char *plus1 = strchr(p, '+');
    if (!plus1) return;

    size_t nlen = (size_t)(plus1 - p);
    if (nlen > 0 && nlen < name_size && out_name && out_name[0] == '\0') {
        memcpy(out_name, p, nlen);
        out_name[nlen] = '\0';
        if (out_name[nlen - 1] != '.' && nlen + 1 < name_size) {
            out_name[nlen] = '.';
            out_name[nlen + 1] = '\0';
        }
    }

    const char *plus2 = strchr(plus1 + 1, '+');
    if (!plus2) return;

    if (out_alg && *out_alg == 0) {
        *out_alg = (uint8_t)atoi(plus1 + 1);
    }

    if (out_tag && *out_tag == 0) {
        *out_tag = (uint16_t)atoi(plus2 + 1);
    }
}

#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

static EVP_PKEY *ec_key_from_raw_priv(int alg, const uint8_t *priv_bytes, size_t priv_len) {
    int nid = (alg == 14) ? NID_secp384r1 : NID_X9_62_prime256v1;
    EC_KEY *eckey = EC_KEY_new_by_curve_name(nid);
    if (!eckey) return NULL;
    BIGNUM *priv_bn = BN_bin2bn(priv_bytes, (int)priv_len, NULL);
    if (!priv_bn) {
        EC_KEY_free(eckey);
        return NULL;
    }
    if (EC_KEY_set_private_key(eckey, priv_bn) != 1) {
        BN_free(priv_bn);
        EC_KEY_free(eckey);
        return NULL;
    }
    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    EC_POINT *pub_point = EC_POINT_new(group);
    BN_CTX *ctx = BN_CTX_new();
    bool pub_ok = false;
    if (group && pub_point && ctx) {
        if (EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, ctx) == 1) {
            if (EC_KEY_set_public_key(eckey, pub_point) == 1) {
                pub_ok = true;
            }
        }
    }
    if (ctx) BN_CTX_free(ctx);
    if (pub_point) EC_POINT_free(pub_point);
    BN_free(priv_bn);

    if (!pub_ok) {
        EC_KEY_free(eckey);
        return NULL;
    }
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey || EVP_PKEY_assign_EC_KEY(pkey, eckey) != 1) {
        if (pkey) EVP_PKEY_free(pkey);
        EC_KEY_free(eckey);
        return NULL;
    }
    return pkey;
}

static EVP_PKEY *rsa_key_from_bind_fields(const char *file_buf) {
    char b64[4096];
    uint8_t n_buf[512], e_buf[32], d_buf[512];
    uint8_t p_buf[256], q_buf[256], dp_buf[256], dq_buf[256], qi_buf[256];

    if (!extract_bind_field(file_buf, "Modulus", b64, sizeof(b64))) return NULL;
    size_t n_len = b64_decode_clean(b64, n_buf, sizeof(n_buf));

    if (!extract_bind_field(file_buf, "PublicExponent", b64, sizeof(b64))) return NULL;
    size_t e_len = b64_decode_clean(b64, e_buf, sizeof(e_buf));

    if (!extract_bind_field(file_buf, "PrivateExponent", b64, sizeof(b64))) return NULL;
    size_t d_len = b64_decode_clean(b64, d_buf, sizeof(d_buf));

    if (n_len == 0 || e_len == 0 || d_len == 0) return NULL;

    RSA *rsa = RSA_new();
    if (!rsa) return NULL;

    BIGNUM *n = BN_bin2bn(n_buf, (int)n_len, NULL);
    BIGNUM *e = BN_bin2bn(e_buf, (int)e_len, NULL);
    BIGNUM *d = BN_bin2bn(d_buf, (int)d_len, NULL);
    if (!n || !e || !d || RSA_set0_key(rsa, n, e, d) != 1) {
        if (n) BN_free(n);
        if (e) BN_free(e);
        if (d) BN_free(d);
        RSA_free(rsa);
        return NULL;
    }

    if (extract_bind_field(file_buf, "Prime1", b64, sizeof(b64))) {
        size_t p_len = b64_decode_clean(b64, p_buf, sizeof(p_buf));
        if (extract_bind_field(file_buf, "Prime2", b64, sizeof(b64))) {
            size_t q_len = b64_decode_clean(b64, q_buf, sizeof(q_buf));
            if (p_len > 0 && q_len > 0) {
                BIGNUM *p = BN_bin2bn(p_buf, (int)p_len, NULL);
                BIGNUM *q = BN_bin2bn(q_buf, (int)q_len, NULL);
                if (p && q) {
                    RSA_set0_factors(rsa, p, q);
                } else {
                    if (p) BN_free(p);
                    if (q) BN_free(q);
                }
            }
        }
    }

    if (extract_bind_field(file_buf, "Exponent1", b64, sizeof(b64))) {
        size_t dp_len = b64_decode_clean(b64, dp_buf, sizeof(dp_buf));
        if (extract_bind_field(file_buf, "Exponent2", b64, sizeof(b64))) {
            size_t dq_len = b64_decode_clean(b64, dq_buf, sizeof(dq_buf));
            if (extract_bind_field(file_buf, "Coefficient", b64, sizeof(b64))) {
                size_t qi_len = b64_decode_clean(b64, qi_buf, sizeof(qi_buf));
                if (dp_len > 0 && dq_len > 0 && qi_len > 0) {
                    BIGNUM *dmp1 = BN_bin2bn(dp_buf, (int)dp_len, NULL);
                    BIGNUM *dmq1 = BN_bin2bn(dq_buf, (int)dq_len, NULL);
                    BIGNUM *iqmp = BN_bin2bn(qi_buf, (int)qi_len, NULL);
                    if (dmp1 && dmq1 && iqmp) {
                        RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp);
                    } else {
                        if (dmp1) BN_free(dmp1);
                        if (dmq1) BN_free(dmq1);
                        if (iqmp) BN_free(iqmp);
                    }
                }
            }
        }
    }

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey || EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        if (pkey) EVP_PKEY_free(pkey);
        RSA_free(rsa);
        return NULL;
    }
    return pkey;
}

#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

bool load_bind_sig0_private_key(const char *path, sig0_key_t *key) {
    if (!path || !key) return false;
    FILE *f = fopen(path, "r");
    if (!f) return false;

    char file_buf[8192];
    size_t nread = fread(file_buf, 1, sizeof(file_buf) - 1, f);
    fclose(f);
    if (nread == 0) return false;
    file_buf[nread] = '\0';

    if (strstr(file_buf, "Private-key-format:") == NULL) {
        return false;
    }

    char name_from_fn[256] = {0};
    uint8_t alg_from_fn = 0;
    uint16_t tag_from_fn = 0;
    extract_bind_key_info_from_filename(path, name_from_fn, sizeof(name_from_fn), &alg_from_fn, &tag_from_fn);

    char alg_str[64] = {0};
    uint8_t alg = alg_from_fn;
    if (extract_bind_field(file_buf, "Algorithm", alg_str, sizeof(alg_str))) {
        int a = atoi(alg_str);
        if (a > 0 && a <= 255) {
            alg = (uint8_t)a;
        }
    }
    if (key->algorithm != 0) {
        alg = key->algorithm;
    }

    if (name_from_fn[0] == '\0' && !key->signer_name) {
        char key_path[1024];
        size_t plen = strlen(path);
        if (plen > 8 && strcmp(path + plen - 8, ".private") == 0 && plen < sizeof(key_path)) {
            memcpy(key_path, path, plen - 8);
            memcpy(key_path + plen - 8, ".key", 5);
            FILE *kf = fopen(key_path, "r");
            if (kf) {
                char kline[512];
                while (fgets(kline, sizeof(kline), kf)) {
                    char *lp = kline;
                    while (*lp == ' ' || *lp == '\t') lp++;
                    if (*lp == ';' || *lp == '#' || *lp == '\0' || *lp == '\r' || *lp == '\n') continue;
                    char *space = strpbrk(lp, " \t\r\n");
                    if (space) {
                        *space = '\0';
                        size_t dlen = strlen(lp);
                        if (dlen > 0 && dlen < sizeof(name_from_fn)) {
                            memcpy(name_from_fn, lp, dlen);
                            name_from_fn[dlen] = '\0';
                            if (name_from_fn[dlen - 1] != '.' && dlen + 1 < sizeof(name_from_fn)) {
                                name_from_fn[dlen] = '.';
                                name_from_fn[dlen + 1] = '\0';
                            }
                        }
                        break;
                    }
                }
                fclose(kf);
            }
        }
    }

    EVP_PKEY *pkey = NULL;
    if (alg == 15) { // Ed25519
        char b64_priv[512] = {0};
        if (extract_bind_field(file_buf, "PrivateKey", b64_priv, sizeof(b64_priv))) {
            uint8_t raw_priv[64];
            size_t raw_len = b64_decode_clean(b64_priv, raw_priv, sizeof(raw_priv));
            if (raw_len == 32) {
                pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, raw_priv, 32);
            }
        }
    } else if (alg == 13 || alg == 14) { // ECDSA P-256 or P-384
        char b64_priv[512] = {0};
        if (extract_bind_field(file_buf, "PrivateKey", b64_priv, sizeof(b64_priv))) {
            uint8_t raw_priv[128];
            size_t raw_len = b64_decode_clean(b64_priv, raw_priv, sizeof(raw_priv));
            size_t expected_len = (alg == 14) ? 48 : 32;
            if (raw_len == expected_len) {
                pkey = ec_key_from_raw_priv(alg, raw_priv, raw_len);
            }
        }
    } else if (alg == 8) { // RSASHA256
        pkey = rsa_key_from_bind_fields(file_buf);
    } else {
        fprintf(stderr, "error: unsupported BIND DNSSEC algorithm %d for SIG(0)\n", alg);
        return false;
    }

    if (!pkey) {
        fprintf(stderr, "error: failed to reconstruct private key from BIND file '%s'\n", path);
        return false;
    }

    if (key->pkey) {
        EVP_PKEY_free(key->pkey);
        key->pkey = NULL;
    }
    key->pkey = pkey;
    key->algorithm = alg;
    if (key->key_tag == 0 && tag_from_fn > 0) {
        key->key_tag = tag_from_fn;
    }
    if (!key->signer_name && name_from_fn[0] != '\0') {
        key->signer_name = strdup(name_from_fn);
    }

    return true;
}

bool load_sig0_pkey(const char *path, sig0_key_t *key) {
    if (!path || !key) return false;
    if (load_bind_sig0_private_key(path, key)) {
        return true;
    }
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "error: could not open SIG(0) private key file '%s': %s\n", path, strerror(errno));
        return false;
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!pkey) {
        fprintf(stderr, "error: failed to parse PEM private key from '%s'\n", path);
        return false;
    }

    if (key->algorithm == 0) {
        int base_id = EVP_PKEY_base_id(pkey);
        if (base_id == EVP_PKEY_RSA) {
            key->algorithm = 8; // RSASHA256
        } else if (base_id == EVP_PKEY_EC) {
            char curve_name[64] = {0};
            size_t cn_len = 0;
            if (EVP_PKEY_get_utf8_string_param(pkey, "group", curve_name, sizeof(curve_name), &cn_len) == 1) {
                if (strcmp(curve_name, "P-256") == 0 || strcmp(curve_name, "prime256v1") == 0) {
                    key->algorithm = 13; // ECDSAP256SHA256
                } else if (strcmp(curve_name, "P-384") == 0 || strcmp(curve_name, "secp384r1") == 0) {
                    key->algorithm = 14; // ECDSAP384SHA384
                } else {
                    key->algorithm = 13; // Default EC to P-256
                }
            } else {
                key->algorithm = 13; // Default EC to P-256
            }
        } else if (base_id == EVP_PKEY_ED25519) {
            key->algorithm = 15; // ED25519
        } else {
            fprintf(stderr, "error: unsupported private key type (base_id %d) for SIG(0)\n", base_id);
            EVP_PKEY_free(pkey);
            return false;
        }
    }

    if (key->pkey) {
        EVP_PKEY_free(key->pkey);
        key->pkey = NULL;
    }
    key->pkey = pkey;
    return true;
}

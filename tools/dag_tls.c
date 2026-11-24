/* The certificate checks of dag's TLS clients (dag_tls.h): +tls / +https (dag_transport.c) and --replay with tls / doh (dag_replay.c). */
#include "dag_internal.h"
#include "dag_tls.h"

bool dag_tls_ctx_verify(SSL_CTX *ctx, const char *ca_file, bool default_store) {
    if (ca_file) {
        if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) != 1) {
            fprintf(stderr, ";; Error: could not load TLS CA file '%s'\n", ca_file);
            return false;
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    } else if (default_store) {
        SSL_CTX_set_default_verify_paths(ctx);
        static const char *const default_ca_locations[] = {
            "/etc/ssl/cert.pem",
            KARIDNS_SYSCONFDIR "/ssl/cert.pem",
            KARIDNS_PREFIX "/share/certs/ca-root-nss.crt",
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/ca-bundle.pem",
            NULL
        };
        for (int i = 0; default_ca_locations[i]; i++) {
            if (access(default_ca_locations[i], R_OK) == 0) {
                SSL_CTX_load_verify_locations(ctx, default_ca_locations[i], NULL);
                break;
            }
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }
    return true;
}

void dag_tls_ssl_peer(SSL *ssl, const char *raw_sni_host, bool verify) {
    char clean_sni_host[256];
    const char *check_host = raw_sni_host;

    if (!raw_sni_host) return;
    size_t slen = strlen(raw_sni_host);
    if (raw_sni_host[0] == '[' && slen > 2 && raw_sni_host[slen - 1] == ']') {
        size_t inner_len = slen - 2;
        if (inner_len < sizeof(clean_sni_host)) {
            memcpy(clean_sni_host, raw_sni_host + 1, inner_len);
            clean_sni_host[inner_len] = '\0';
            check_host = clean_sni_host;
        }
    } else if (slen > 1 && raw_sni_host[slen - 1] == '.') {
        // RFC 6066 §3: The hostname specification for SNI MUST NOT end with a trailing dot
        size_t inner_len = slen - 1;
        if (inner_len < sizeof(clean_sni_host)) {
            memcpy(clean_sni_host, raw_sni_host, inner_len);
            clean_sni_host[inner_len] = '\0';
            check_host = clean_sni_host;
        }
    }

    struct in_addr a4; struct in6_addr a6;
    bool sni_is_ip = (inet_pton(AF_INET, check_host, &a4) == 1 || inet_pton(AF_INET6, check_host, &a6) == 1);
    if (!sni_is_ip) {
        SSL_set_tlsext_host_name(ssl, check_host);
    }

    /* 証明書検証を行うモード(tls_ca_fileまたはtls_verify_default_store指定時)
       のみ、ホスト名検証パラメータを明示的に設定する */
    if (verify) {
        if (sni_is_ip) {
            X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
            X509_VERIFY_PARAM_set1_ip_asc(vpm, check_host);
        } else {
            SSL_set1_host(ssl, check_host);
        }
    }
}


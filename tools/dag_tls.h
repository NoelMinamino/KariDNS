#ifndef DAG_TLS_H
#define DAG_TLS_H

#include <stdbool.h>
#include <stddef.h>
#include <openssl/ssl.h>

/* The certificate checks of dag's TLS clients (+tls / +https and --replay with tls or doh), in one place (dag_transport.c).
 *
 * dag_tls_ctx_verify(): +tls-ca=FILE loads FILE, +tls-ca the system store (the default locations), and the context then
 * verifies the peer (SSL_VERIFY_PEER); with neither the peer is not verified (opportunistic TLS, RFC 7858 §4.1 / RFC 8310
 * §5).  false only when FILE cannot be loaded (the message is printed).
 *
 * dag_tls_ssl_peer(): the SNI (RFC 6066 §3: a host name without the trailing dot, never an address) of host, and with verify
 * the name or the address the certificate must carry (RFC 6125 / RFC 8310 §8.1); host may be "[v6addr]". */
bool dag_tls_ctx_verify(SSL_CTX *ctx, const char *ca_file, bool default_store);
void dag_tls_ssl_peer(SSL *ssl, const char *host, bool verify);

#endif /* DAG_TLS_H */

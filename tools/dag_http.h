#ifndef DAG_HTTP_H
#define DAG_HTTP_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* HTTP status code of a response header ("HTTP/1.1 200 OK" -> 200), or -1. */
int parse_http_status_code(const uint8_t *buf, size_t len);

/* Extracts the DNS message from a raw HTTP response (header + body; Content-Length or
 * chunked, RFC 7230 section 3.3.3). Returns the message length, or -1 when the response
 * is incomplete, malformed, not 200 OK, or larger than resp_cap. */
ssize_t decode_http_response_body(const uint8_t *http_buf, size_t http_len,
                                  uint8_t *resp, size_t resp_cap);

#endif /* DAG_HTTP_H */

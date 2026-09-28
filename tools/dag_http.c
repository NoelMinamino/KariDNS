/*
 * dag_http.c - HTTP/1.1 response parsing for DNS over HTTPS (RFC 8484 / RFC 7230).
 *
 * Pure functions without network or global state, shared by the dag client
 * (dag_transport.c) and the parallel replay workers (dag_replay.c).
 */
#include "dag_internal.h"
#include "dag_http.h"

// HTTP Chunked 転送の次のチャンクを解析するヘルパー関数 (RFC 7230 §4.1)
static bool parse_http_chunk(const uint8_t *buf, size_t buf_len, size_t *inout_offset,
                             size_t *out_data_offset, size_t *out_chunk_len, bool *out_is_final) {
    if (!buf || !inout_offset || !out_data_offset || !out_chunk_len || !out_is_final) return false;
    if (*inout_offset >= buf_len) return false;

    const uint8_t *p = buf + *inout_offset;
    size_t rem = buf_len - *inout_offset;

    const uint8_t *line_end = memmem(p, rem, "\r\n", 2);
    if (!line_end) return false;

    // chunk-size (1*HEXDIG) を line_end の手前まで安全にパース
    const uint8_t *cur = p;
    while (cur < line_end && (*cur == ' ' || *cur == '\t')) cur++;
    if (cur == line_end) return false;

    size_t chunk_sz = 0;
    int hex_digits = 0;
    while (cur < line_end) {
        uint8_t c = *cur;
        int val = -1;
        if (c >= '0' && c <= '9') val = c - '0';
        else if (c >= 'a' && c <= 'f') val = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') val = c - 'A' + 10;
        else break; // chunk-ext (;name=val) または空白

        if (chunk_sz > (SIZE_MAX / 16)) return false;
        chunk_sz = chunk_sz * 16 + (size_t)val;
        cur++;
        hex_digits++;
    }
    if (hex_digits == 0) return false;

    // chunk-sizeの直後: 空白スキップ後、行末かまたは ';' で始まる chunk-ext のみ許容 (RFC 7230 §4.1)
    while (cur < line_end && (*cur == ' ' || *cur == '\t')) cur++;
    if (cur < line_end && *cur != ';') return false;

    size_t data_start = (size_t)(line_end - buf) + 2;
    if (chunk_sz == 0) {
        *out_data_offset = data_start;
        *out_chunk_len = 0;
        *out_is_final = true;
        size_t after_line = (size_t)(line_end - p);
        if (after_line + 2 > rem) return false;
        // 最終チャンク: line_end から始まるトレイラーヘッダ終端 (\r\n\r\n) を探索
        const uint8_t *final_end = memmem(line_end, rem - after_line, "\r\n\r\n", 4);
        if (final_end) {
            *inout_offset = (size_t)(final_end - buf) + 4;
            return true;
        }
        return false;
    }

    // chunk_data + CRLF (2バイト) がバッファ内に収まるかを安全に検証 (オーバーフロー防止)
    if (data_start > buf_len || buf_len - data_start < 2) return false;
    if (chunk_sz > buf_len - data_start - 2) return false;

    size_t data_end = data_start + chunk_sz;
    // RFC 7230 §4.1: chunk-data の直後は必ず CRLF
    if (buf[data_end] != '\r' || buf[data_end + 1] != '\n') return false;

    *out_data_offset = data_start;
    *out_chunk_len = chunk_sz;
    *out_is_final = false;
    *inout_offset = data_end + 2;
    return true;
}

// HTTPレスポンスのステータスコードを安全に抽出 (バッファ境界チェック付き、NUL終端非依存)
int parse_http_status_code(const uint8_t *buf, size_t len) {
    if (!buf || len < 12) return -1;
    if (strncmp((const char *)buf, "HTTP/", 5) != 0) return -1;
    const uint8_t *p = buf + 5;
    const uint8_t *end = buf + len;
    // HTTPバージョン文字列 (例: "1.1", "2") をスキップ
    while (p < end && *p != ' ' && *p != '\r' && *p != '\n') p++;
    // ステータスコード直前の空白をスキップ
    while (p < end && *p == ' ') p++;
    int code = 0, digits = 0;
    while (p < end && *p >= '0' && *p <= '9' && digits < 3) {
        code = code * 10 + (*p - '0');
        p++;
        digits++;
    }
    if (digits < 3) return -1;
    if (p < end && *p >= '0' && *p <= '9') return -1; // 4桁以上は無効
    if (p < end && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') return -1;
    return code;
}

// HTTPレスポンス(ヘッダ+ボディ)からDNSメッセージをデコードする純粋関数 (RFC 7230 / RFC 8484)
// http_buf/http_len: 受信済みの生HTTPレスポンス
// resp/resp_cap: デコード結果(DNSメッセージ)の出力バッファ
// 戻り値: 成功時はデコードしたバイト数(>=0)。未完了・不正フォーマット時は -1。
ssize_t decode_http_response_body(const uint8_t *http_buf, size_t http_len,
                                  uint8_t *resp, size_t resp_cap) {
    if (!http_buf || http_len < 16 || !resp || resp_cap == 0) return -1;

    const uint8_t *hdr_end_u8 = memmem(http_buf, http_len, "\r\n\r\n", 4);
    if (!hdr_end_u8) return -1;

    size_t header_len = (size_t)(hdr_end_u8 - http_buf);
    size_t body_offset = header_len + 4;
    size_t body_len = http_len - body_offset;

    // RFC 8484 §4.2.1: HTTP 200 OK の検証
    int status_code = parse_http_status_code(http_buf, header_len);
    if (status_code != 200) return -1;

    // RFC 7230 §3.3.3: Transfer-Encoding takes precedence over Content-Length
    bool is_chunked = false;
    for (size_t i = 0; i + 18 <= header_len; i++) {
        if ((i == 0 || http_buf[i - 1] == '\n') &&
            strncasecmp((const char *)http_buf + i, "Transfer-Encoding:", 18) == 0) {
            for (size_t j = i + 18; j + 7 <= header_len; j++) {
                if (http_buf[j] == '\r' || http_buf[j] == '\n') break;
                bool prev_delim = (j == i + 18 || http_buf[j - 1] == ' ' || http_buf[j - 1] == '\t' || http_buf[j - 1] == ',');
                if (prev_delim && strncasecmp((const char *)http_buf + j, "chunked", 7) == 0) {
                    bool next_delim = (j + 7 == header_len || http_buf[j + 7] == ' ' || http_buf[j + 7] == '\t' ||
                                       http_buf[j + 7] == '\r' || http_buf[j + 7] == '\n' || http_buf[j + 7] == ',' ||
                                       http_buf[j + 7] == ';');
                    if (next_delim) {
                        is_chunked = true;
                        break;
                    }
                }
            }
            if (is_chunked) break;
        }
    }

    if (is_chunked) {
        size_t src = body_offset;
        size_t dst = 0;
        bool chunk_complete = false;
        size_t data_off, chunk_len;
        bool is_final = false;
        while (parse_http_chunk(http_buf, http_len, &src, &data_off, &chunk_len, &is_final)) {
            if (is_final) {
                chunk_complete = true;
                break;
            }
            if (data_off > http_len || chunk_len > http_len - data_off) {
                return -1;
            }
            if (dst > resp_cap || chunk_len > resp_cap - dst) {
                return -1;
            }
            if (chunk_len > 0) {
                memcpy(resp + dst, http_buf + data_off, chunk_len);
                dst += chunk_len;
            }
        }
        if (!chunk_complete) return -1;
        return (ssize_t)dst;
    }

    // Content-Length の判定
    size_t cl_val = 0;
    bool found_cl = false;
    for (size_t i = 0; i + 15 <= header_len; i++) {
        if ((i == 0 || http_buf[i - 1] == '\n') &&
            strncasecmp((const char *)http_buf + i, "Content-Length:", 15) == 0) {
            const uint8_t *cur = http_buf + i + 15;
            const uint8_t *end = http_buf + header_len;
            while (cur < end && (*cur == ' ' || *cur == '\t')) cur++;
            size_t val = 0;
            bool has_digits = false;
            while (cur < end && *cur >= '0' && *cur <= '9') {
                if (val > (SIZE_MAX / 10)) { val = SIZE_MAX; break; }
                val = val * 10 + (*cur - '0');
                cur++;
                has_digits = true;
            }
            if (has_digits) {
                while (cur < end && (*cur == ' ' || *cur == '\t')) cur++;
                if (cur < end && *cur != '\r' && *cur != '\n') {
                    return -1; // 不正なContent-Length値
                }
                if (found_cl && cl_val != val) {
                    return -1; // RFC 7230 §3.3.2: 異なるContent-Lengthの重複
                }
                cl_val = val;
                found_cl = true;
            } else {
                return -1; // 数字の無いContent-Lengthヘッダは不正
            }
        }
    }
    if (found_cl) {
        if (cl_val > resp_cap) return -1;
        if (body_len < cl_val) return -1;
        if (cl_val < body_len) body_len = cl_val;
    }

    if (body_len > resp_cap) return -1;
    if (body_offset > http_len || body_len > http_len - body_offset) return -1;
    memcpy(resp, http_buf + body_offset, body_len);
    return (ssize_t)body_len;
}

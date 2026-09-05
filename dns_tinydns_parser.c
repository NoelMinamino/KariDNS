#include "dns_zone_parser.h"
#include "dns_wire.h"
#include "dns_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <math.h>

#define TTL_NS 259200UL
#define TTL_POSITIVE 86400UL
#define TTL_NEGATIVE 2560UL
#define TINYDNS_NUMFIELDS 15

#define DEFAULT_SOA_REFRESH 16384UL
#define DEFAULT_SOA_RETRY   2048UL
#define DEFAULT_SOA_EXPIRE  1048576UL
#define DEFAULT_SOA_MINIMUM 2560UL

/* ============================================================================
 * ゾーン振り分け・親子ゾーン重複登録防止判定
 * ============================================================================ */
static bool is_record_owned_by_zone(const char *record_name, const char *target_zone, const char **all_zones, int all_zone_count) {
    if (!record_name || !target_zone || !*target_zone) return true;

    size_t rlen = strlen(record_name);
    size_t tlen = strlen(target_zone);

    // target_zone へのサフィックス一致確認 (末尾一致 + ラベル境界)
    if (rlen < tlen) return false;
    if (strcasecmp(record_name + (rlen - tlen), target_zone) != 0) return false;
    if (rlen > tlen && record_name[rlen - tlen - 1] != '.') return false;

    // 親子ゾーン重複防止: all_zones の中で record_name に最長一致するゾーンを探す
    if (all_zones && all_zone_count > 0) {
        size_t longest_len = 0;
        for (int i = 0; i < all_zone_count; i++) {
            const char *z = all_zones[i];
            if (!z) continue;
            size_t zlen = strlen(z);
            if (rlen >= zlen && strcasecmp(record_name + (rlen - zlen), z) == 0) {
                if (rlen == zlen || record_name[rlen - zlen - 1] == '.') {
                    if (zlen > longest_len) {
                        longest_len = zlen;
                    }
                }
            }
        }
        if (longest_len > tlen) {
            // 他により長く一致する子ゾーンが存在するため、親ゾーン側には登録しない
            return false;
        }
    }

    return true;
}

/* ============================================================================
 * セクション2-1(a): FQDNフィールド用デコーダ
 * ドット区切り、空ラベルは黙って読み飛ばす(先頭/末尾/連続ドット許容)、
 * \nnn(8進数、最大3桁)と \x(リテラル文字)エスケープに対応。
 * 出力は末尾ドット付きの表示形式文字列("example.com." のような形)。
 * ============================================================================ */
static char *tinydns_decode_fqdn(zone_arena_t *arena, const char *field, size_t flen) {
    char label[64];
    size_t labellen = 0;
    char out[512];
    size_t outlen = 0;
    size_t i = 0;

    while (i < flen) {
        char ch = field[i++];
        if (ch == '.') {
            if (labellen > 0) {
                if (outlen + labellen + 1 >= sizeof(out)) return NULL; // FQDN超過
                memcpy(out + outlen, label, labellen);
                outlen += labellen;
                out[outlen++] = '.';
                labellen = 0;
            }
            continue; // 連続ドットや先頭ドットは読み飛ばす
        }
        if (ch == '\\' && i < flen) {
            ch = field[i++];
            if (ch >= '0' && ch <= '7') {
                int val = ch - '0';
                if (i < flen && field[i] >= '0' && field[i] <= '7') {
                    val = (val << 3) + (field[i++] - '0');
                    if (i < flen && field[i] >= '0' && field[i] <= '7') {
                        val = (val << 3) + (field[i++] - '0');
                    }
                }
                ch = (char)(uint8_t)val;
            }
        }
        if (labellen >= 63) return NULL; // ラベル長63バイト超過
        label[labellen++] = ch;
    }

    if (labellen > 0) {
        if (outlen + labellen + 1 >= sizeof(out)) return NULL;
        memcpy(out + outlen, label, labellen);
        outlen += labellen;
        out[outlen++] = '.';
    }

    if (outlen == 0) {
        out[outlen++] = '.'; // 空FQDN = ルート "."
    }
    out[outlen] = '\0';

    return arena_strdup(arena, out);
}

/* ============================================================================
 * セクション2-1(b): TXT/汎用レコードrdata用デコーダ(\nnnのみ対応、ドットは素通り)
 * ============================================================================ */
static uint8_t *tinydns_decode_bytes(zone_arena_t *arena, const char *field, size_t flen, size_t *out_len) {
    uint8_t *buf = (uint8_t *)arena_alloc(arena, flen + 1);
    if (!buf) {
        *out_len = 0;
        return NULL;
    }
    size_t j = 0, i = 0;
    while (i < flen) {
        char ch = field[i++];
        if (ch == '\\' && i < flen) {
            ch = field[i++];
            if (ch >= '0' && ch <= '7') {
                int val = ch - '0';
                if (i < flen && field[i] >= '0' && field[i] <= '7') {
                    val = (val << 3) + (field[i++] - '0');
                    if (i < flen && field[i] >= '0' && field[i] <= '7') {
                        val = (val << 3) + (field[i++] - '0');
                    }
                }
                ch = (char)(uint8_t)val;
            }
        }
        buf[j++] = (uint8_t)ch;
    }
    buf[j] = '\0';
    *out_len = j;
    return buf;
}

/* ============================================================================
 * セクション3: 緩いIPv4パース
 * オクテット範囲チェックなし(下位8bitのみ採用)、末尾ゴミ文字許容。
 * ============================================================================ */
static bool tinydns_ip4_scan(const char *s, size_t len, uint8_t ip[4]) {
    size_t pos = 0;
    for (int oct = 0; oct < 4; oct++) {
        if (oct > 0) {
            if (pos >= len || s[pos] != '.') return false;
            pos++;
        }
        size_t start = pos;
        unsigned long val = 0;
        while (pos < len && isdigit((unsigned char)s[pos])) {
            val = val * 10 + (s[pos] - '0');
            pos++;
        }
        if (pos == start) return false; // 数字が1つもない
        ip[oct] = (uint8_t)(val & 0xFF); // 範囲チェックなし、下位8bit採用
    }
    return true;
}

#define TAI64_UNIX_EPOCH_OFFSET 4611686018427387904ULL /* 0x4000000000000000 */

/* timestampフィールド(0〜16桁の16進数)をUnix時刻へ変換する。
 * ttdparse()と同じ緩さ: 不正な文字は0として扱い、16桁未満なら
 * 残りをゼロ埋めする。エラーは返さない。
 * フィールドが完全に空(flen==0)の場合は *has_ts に false を設定する。 */
static void tinydns_parse_timestamp(const char *field, size_t flen, bool *has_ts, time_t *out_unix) {
    if (flen == 0) {
        *has_ts = false;
        *out_unix = 0;
        return;
    }
    uint64_t tai64 = 0;
    for (size_t i = 0; i < 16; i++) {
        int nibble = 0;
        if (i < flen) {
            char ch = field[i];
            if (ch >= '0' && ch <= '9') nibble = ch - '0';
            else if (ch >= 'a' && ch <= 'f') nibble = ch - 'a' + 10;
            else if (ch >= 'A' && ch <= 'F') nibble = ch - 'A' + 10; /* ttdparse本体は大文字A-Fを
                                                                        受け付けないが、実用上は
                                                                        許容しておいて害はない */
            else nibble = 0;
        }
        tai64 = (tai64 << 4) | (uint64_t)nibble;
    }
    *has_ts = true;
    if (tai64 < TAI64_UNIX_EPOCH_OFFSET) {
        *out_unix = 0; /* 変換不能なほど小さい値。実運用ではまず起こらない */
    } else {
        *out_unix = (time_t)(tai64 - TAI64_UNIX_EPOCH_OFFSET);
    }
}

/* timestampフィールドを解析し、ttdとcountdownフラグを格納する(案A: リアルタイム評価用)。
 * パーサー内ではスキップ判定を行わず、dns_record_tにttd情報を保持させてクエリ時に評価する。 */
static void tinydns_parse_ttd_field(const char *ts_field, size_t ts_len,
                                    bool *has_ttd, time_t *ttd_out, bool is_ttl_zero) {
    bool has_ts = false;
    time_t cutoff = 0;
    tinydns_parse_timestamp(ts_field, ts_len, &has_ts, &cutoff);
    *has_ttd = has_ts;
    *ttd_out = cutoff;
    (void)is_ttl_zero;
}

/* ============================================================================
 * ヘルパー: x展開ルール (., &, @ 用)
 * xに '.' が含まれていなければ x + suffix + fqdn として展開
 * ============================================================================ */
static char *tinydns_expand_x(zone_arena_t *arena, const char *x_field, size_t x_len, const char *suffix, const char *fqdn) {
    bool has_dot = false;
    for (size_t i = 0; i < x_len; i++) {
        if (x_field[i] == '.') {
            has_dot = true;
            break;
        }
    }
    if (!has_dot) {
        // x + suffix + fqdn
        // tinydns_decode_fqdn は先頭ドットや連続ドットを無視するため、
        // x_len == 0 の時は ".ns." + fqdn -> ns.<fqdn> となる
        size_t fqdn_len = fqdn ? strlen(fqdn) : 0;
        size_t suf_len = strlen(suffix);
        size_t combined_len = x_len + suf_len + fqdn_len;
        char *comb = malloc(combined_len + 1);
        if (!comb) return NULL;
        if (x_len > 0) memcpy(comb, x_field, x_len);
        memcpy(comb + x_len, suffix, suf_len);
        if (fqdn_len > 0) memcpy(comb + x_len + suf_len, fqdn, fqdn_len);
        comb[combined_len] = '\0';

        char *res = tinydns_decode_fqdn(arena, comb, combined_len);
        free(comb);
        return res;
    } else {
        return tinydns_decode_fqdn(arena, x_field, x_len);
    }
}

/* ============================================================================
 * レコード確保ヘルパー
 * ============================================================================ */
static dns_record_t *tinydns_new_record(zone_arena_t *arena, parse_context_t *ctx,
                                        const char *line_start, const char *buf,
                                        char *owner, const char *type_str,
                                        uint16_t type_code, unsigned long ttl,
                                        const char *ts_field, size_t ts_len,
                                        const char *lo_field, size_t lo_len) {
    dns_record_t *rec = arena_alloc_record(arena, ctx, line_start, buf);
    if (!rec) return NULL;
    rec->name = owner;
    rec->type = arena_strdup(arena, type_str);
    rec->type_code = type_code;
    rec->ttl_value = (uint32_t)ttl;
    rec->class_val = 1; // IN
    rec->class_str = "IN";
    char *ttl_buf = arena_alloc(arena, 16);
    if (ttl_buf) {
        snprintf(ttl_buf, 16, "%lu", ttl);
        rec->ttl = ttl_buf;
    }

    bool has_ttd = false;
    time_t ttd = 0;
    tinydns_parse_ttd_field(ts_field, ts_len, &has_ttd, &ttd, ttl == 0);
    rec->tinydns_ttd = has_ttd ? ttd : 0;
    rec->tinydns_ttl_countdown = has_ttd && (ttl == 0);

    rec->tinydns_loc[0] = lo_len > 0 ? lo_field[0] : 0;
    rec->tinydns_loc[1] = lo_len > 1 ? lo_field[1] : 0;

    return rec;
}

/* ============================================================================
 * 1行処理関数
 * ============================================================================ */
static bool tinydns_process_line(zone_arena_t *arena, parse_context_t *ctx,
                                 const char *line_start, const char *buf,
                                 char typech, char *f[TINYDNS_NUMFIELDS],
                                 size_t flen[TINYDNS_NUMFIELDS],
                                 uint32_t default_serial,
                                 unsigned long linenum) {
    const char *target_zone = ctx ? ctx->default_origin : NULL;
    const char **all_zones = ctx ? ctx->all_zone_names : NULL;
    int all_zone_count = ctx ? ctx->all_zone_count : 0;

    switch (typech) {
        case '.':   // SOA + NS (+ 任意A)
        case '&': { // NS (+ 任意A)
            char *fqdn = tinydns_decode_fqdn(arena, f[0], flen[0]);
            if (!fqdn) {
                if (ctx && ctx->err_out) {
                    ctx->err_out->error_message = "Invalid FQDN in tinydns record";
                    ctx->err_out->error_offset = (size_t)(line_start - buf);
                    ctx->err_out->token_length = flen[0];
                }
                return false;
            }

            char *x = tinydns_expand_x(arena, f[2], flen[2], ".ns.", fqdn);
            if (!x) {
                if (ctx && ctx->err_out) {
                    ctx->err_out->error_message = "Invalid NS target FQDN";
                    ctx->err_out->error_offset = (size_t)(line_start - buf);
                    ctx->err_out->token_length = flen[2];
                }
                return false;
            }

            unsigned long ttl = TTL_NS;
            if (flen[3] > 0) ttl = strtoul(f[3], NULL, 10);

            if (typech == '.') {
                // SOA レコード
                if (is_record_owned_by_zone(fqdn, target_zone, all_zones, all_zone_count)) {
                    // SOA自身のTTL: f[3]が明示的に "0" の場合のみ 0、それ以外(省略含む)は 2560
                    unsigned long soa_ttl = TTL_NEGATIVE;
                    if (flen[3] > 0 && flen[3] == 1 && f[3][0] == '0') soa_ttl = 0;

                    // rname は "\12hostmaster" + fqdn
                    char rname_buf[512];
                    snprintf(rname_buf, sizeof(rname_buf), "hostmaster.%s", fqdn);
                    char *rname = tinydns_decode_fqdn(arena, rname_buf, strlen(rname_buf));

                    dns_record_t *soa_rec = tinydns_new_record(arena, ctx, line_start, buf, fqdn, "SOA", 6, soa_ttl, f[4], flen[4], f[5], flen[5]);
                    if (!soa_rec) return false;

                    char s_ser[32], s_ref[32], s_ret[32], s_exp[32], s_min[32];
                    snprintf(s_ser, sizeof(s_ser), "%u", default_serial);
                    snprintf(s_ref, sizeof(s_ref), "%lu", DEFAULT_SOA_REFRESH);
                    snprintf(s_ret, sizeof(s_ret), "%lu", DEFAULT_SOA_RETRY);
                    snprintf(s_exp, sizeof(s_exp), "%lu", DEFAULT_SOA_EXPIRE);
                    snprintf(s_min, sizeof(s_min), "%lu", DEFAULT_SOA_MINIMUM);

                    soa_rec->rdata[0] = x;
                    soa_rec->rdata[1] = rname ? rname : arena_strdup(arena, "hostmaster.");
                    soa_rec->rdata[2] = arena_strdup(arena, s_ser);
                    soa_rec->rdata[3] = arena_strdup(arena, s_ref);
                    soa_rec->rdata[4] = arena_strdup(arena, s_ret);
                    soa_rec->rdata[5] = arena_strdup(arena, s_exp);
                    soa_rec->rdata[6] = arena_strdup(arena, s_min);
                    soa_rec->rdata_count = 7;
                }
            }

            // NS レコード
            if (is_record_owned_by_zone(fqdn, target_zone, all_zones, all_zone_count)) {
                dns_record_t *ns_rec = tinydns_new_record(arena, ctx, line_start, buf, fqdn, "NS", 2, ttl, f[4], flen[4], f[5], flen[5]);
                if (!ns_rec) return false;
                ns_rec->rdata[0] = x;
                ns_rec->rdata_count = 1;
            }

            // 連動 A レコード (ip有効時)
            uint8_t ip[4];
            if (flen[1] > 0 && tinydns_ip4_scan(f[1], flen[1], ip)) {
                if (is_record_owned_by_zone(x, target_zone, all_zones, all_zone_count)) {
                    char ipstr[16];
                    snprintf(ipstr, sizeof(ipstr), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
                    dns_record_t *a_rec = tinydns_new_record(arena, ctx, line_start, buf, x, "A", 1, ttl, f[4], flen[4], f[5], flen[5]);
                    if (!a_rec) return false;
                    a_rec->rdata[0] = arena_strdup(arena, ipstr);
                    a_rec->rdata_count = 1;
                }
            }
            return true;
        }

        case '+':   // A のみ
        case '=': { // A + PTR
            char *owner = tinydns_decode_fqdn(arena, f[0], flen[0]);
            if (!owner) {
                if (ctx && ctx->err_out) {
                    ctx->err_out->error_message = "Invalid FQDN in tinydns record";
                    ctx->err_out->error_offset = (size_t)(line_start - buf);
                    ctx->err_out->token_length = flen[0];
                }
                return false;
            }

            unsigned long ttl = TTL_POSITIVE;
            if (flen[2] > 0) ttl = strtoul(f[2], NULL, 10);

            uint8_t ip[4];
            if (flen[1] > 0 && tinydns_ip4_scan(f[1], flen[1], ip)) {
                // A レコード生成
                if (is_record_owned_by_zone(owner, target_zone, all_zones, all_zone_count)) {
                    char ipstr[16];
                    snprintf(ipstr, sizeof(ipstr), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
                    dns_record_t *a_rec = tinydns_new_record(arena, ctx, line_start, buf, owner, "A", 1, ttl, f[3], flen[3], f[4], flen[4]);
                    if (!a_rec) return false;
                    a_rec->rdata[0] = arena_strdup(arena, ipstr);
                    a_rec->rdata_count = 1;
                }

                // PTR レコード生成 ('=' の場合のみ)
                if (typech == '=') {
                    char ptr_name[64];
                    snprintf(ptr_name, sizeof(ptr_name), "%u.%u.%u.%u.in-addr.arpa.", ip[3], ip[2], ip[1], ip[0]);
                    if (is_record_owned_by_zone(ptr_name, target_zone, all_zones, all_zone_count)) {
                        dns_record_t *ptr_rec = tinydns_new_record(arena, ctx, line_start, buf,
                                                                   arena_strdup(arena, ptr_name),
                                                                   "PTR", 12, ttl, f[3], flen[3], f[4], flen[4]);
                        if (!ptr_rec) return false;
                        ptr_rec->rdata[0] = owner;
                        ptr_rec->rdata_count = 1;
                    }
                }
            }
            return true;
        }

        case '@': { // MX (+ 任意A)
            char *fqdn = tinydns_decode_fqdn(arena, f[0], flen[0]);
            if (!fqdn) {
                if (ctx && ctx->err_out) {
                    ctx->err_out->error_message = "Invalid FQDN in tinydns @ record";
                    ctx->err_out->error_offset = (size_t)(line_start - buf);
                    ctx->err_out->token_length = flen[0];
                }
                return false;
            }

            char *x = tinydns_expand_x(arena, f[2], flen[2], ".mx.", fqdn);
            if (!x) {
                if (ctx && ctx->err_out) {
                    ctx->err_out->error_message = "Invalid MX target FQDN";
                    ctx->err_out->error_offset = (size_t)(line_start - buf);
                    ctx->err_out->token_length = flen[2];
                }
                return false;
            }

            unsigned long dist = 0;
            if (flen[3] > 0) dist = strtoul(f[3], NULL, 10);

            unsigned long ttl = TTL_POSITIVE;
            if (flen[4] > 0) ttl = strtoul(f[4], NULL, 10);

            if (is_record_owned_by_zone(fqdn, target_zone, all_zones, all_zone_count)) {
                dns_record_t *mx_rec = tinydns_new_record(arena, ctx, line_start, buf, fqdn, "MX", 15, ttl, f[5], flen[5], f[6], flen[6]);
                if (!mx_rec) return false;
                char dist_str[16];
                snprintf(dist_str, sizeof(dist_str), "%lu", dist);
                mx_rec->rdata[0] = arena_strdup(arena, dist_str);
                mx_rec->rdata[1] = x;
                mx_rec->rdata_count = 2;
            }

            // 連動 A レコード (ip有効時)
            uint8_t ip[4];
            if (flen[1] > 0 && tinydns_ip4_scan(f[1], flen[1], ip)) {
                if (is_record_owned_by_zone(x, target_zone, all_zones, all_zone_count)) {
                    char ipstr[16];
                    snprintf(ipstr, sizeof(ipstr), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
                    dns_record_t *a_rec = tinydns_new_record(arena, ctx, line_start, buf, x, "A", 1, ttl, f[5], flen[5], f[6], flen[6]);
                    if (!a_rec) return false;
                    a_rec->rdata[0] = arena_strdup(arena, ipstr);
                    a_rec->rdata_count = 1;
                }
            }
            return true;
        }

        case '\'': { // TXT
            char *fqdn = tinydns_decode_fqdn(arena, f[0], flen[0]);
            if (!fqdn) {
                if (ctx && ctx->err_out) {
                    ctx->err_out->error_message = "Invalid FQDN in tinydns TXT record";
                    ctx->err_out->error_offset = (size_t)(line_start - buf);
                    ctx->err_out->token_length = flen[0];
                }
                return false;
            }

            unsigned long ttl = TTL_POSITIVE;
            if (flen[2] > 0) ttl = strtoul(f[2], NULL, 10);

            if (is_record_owned_by_zone(fqdn, target_zone, all_zones, all_zone_count)) {
                size_t raw_len = 0;
                uint8_t *raw_bytes = tinydns_decode_bytes(arena, f[1], flen[1], &raw_len);
                if (!raw_bytes && flen[1] > 0) return false;

                if (raw_len > MAX_RDATA * 127) {
                    if (ctx && ctx->err_out) {
                        ctx->err_out->error_message = "TXT record data exceeds maximum supported length (6096 bytes)";
                        ctx->err_out->error_offset = (size_t)(line_start - buf);
                        ctx->err_out->token_length = flen[1];
                    }
                    return false;
                }

                dns_record_t *txt_rec = tinydns_new_record(arena, ctx, line_start, buf, fqdn, "TXT", 16, ttl, f[3], flen[3], f[4], flen[4]);
                if (!txt_rec) return false;

                /* ============================================================
                 * [重要/設計注記: TXT 127バイトチャンク分割]
                 * 本家 tinydns は TXT レコードを 127 バイトごとの character-string
                 * に分割してワイヤフォーマットへ格納します。
                 * KariDNS の serialize_dns_record() は各 rdata[i] が 255 バイト以下
                 * であればそのまま 1 つの character-string として出力するため、
                 * ここで必ず 127 バイト以下のチャンクに分割して rdata[] に格納する
                 * 必要があります。
                 * ⚠️ 未分割の長い文字列を rdata[0] にそのまま渡してしまうと、
                 * シリアライザの安全弁が 255 バイト単位で再分割してしまい、
                 * 本家 tinydns の 127 バイト境界と静かに乖離する原因になります。
                 * ============================================================ */
                if (raw_len == 0) {
                    txt_rec->rdata[0] = arena_strdup(arena, "");
                    txt_rec->rdata_count = 1;
                } else {
                    size_t offset = 0;
                    int chunk_idx = 0;
                    while (offset < raw_len && chunk_idx < MAX_RDATA) {
                        size_t clen = raw_len - offset;
                        if (clen > 127) clen = 127;
                        char *chunk = (char *)arena_alloc(arena, clen + 1);
                        if (!chunk) return false;
                        memcpy(chunk, raw_bytes + offset, clen);
                        chunk[clen] = '\0';
                        txt_rec->rdata[chunk_idx++] = chunk;
                        offset += clen;
                    }
                    txt_rec->rdata_count = chunk_idx;
                }
            }
            return true;
        }

        case '^':   // PTR のみ
        case 'C': { // CNAME
            char *fqdn = tinydns_decode_fqdn(arena, f[0], flen[0]);
            if (!fqdn) {
                if (ctx && ctx->err_out) {
                    ctx->err_out->error_message = "Invalid FQDN in tinydns PTR/CNAME record";
                    ctx->err_out->error_offset = (size_t)(line_start - buf);
                    ctx->err_out->token_length = flen[0];
                }
                return false;
            }

            char *target = tinydns_decode_fqdn(arena, f[1], flen[1]);
            if (!target) {
                if (ctx && ctx->err_out) {
                    ctx->err_out->error_message = "Invalid target FQDN in tinydns PTR/CNAME record";
                    ctx->err_out->error_offset = (size_t)(line_start - buf);
                    ctx->err_out->token_length = flen[1];
                }
                return false;
            }

            unsigned long ttl = TTL_POSITIVE;
            if (flen[2] > 0) ttl = strtoul(f[2], NULL, 10);

            if (is_record_owned_by_zone(fqdn, target_zone, all_zones, all_zone_count)) {
                const char *tname = (typech == 'C') ? "CNAME" : "PTR";
                uint16_t tcode = (typech == 'C') ? 5 : 12;
                dns_record_t *rec = tinydns_new_record(arena, ctx, line_start, buf, fqdn, tname, tcode, ttl, f[3], flen[3], f[4], flen[4]);
                if (!rec) return false;
                rec->rdata[0] = target;
                rec->rdata_count = 1;
            }
            return true;
        }

        case 'Z': { // 完全SOA
            char *fqdn = tinydns_decode_fqdn(arena, f[0], flen[0]);
            if (!fqdn) {
                if (ctx && ctx->err_out) {
                    ctx->err_out->error_message = "Invalid FQDN in tinydns Z record";
                    ctx->err_out->error_offset = (size_t)(line_start - buf);
                    ctx->err_out->token_length = flen[0];
                }
                return false;
            }

            char *mname = tinydns_decode_fqdn(arena, f[1], flen[1]);
            char *rname = tinydns_decode_fqdn(arena, f[2], flen[2]);
            if (!mname || !rname) {
                if (ctx && ctx->err_out) {
                    ctx->err_out->error_message = "Invalid mname/rname in tinydns Z record";
                    ctx->err_out->error_offset = (size_t)(line_start - buf);
                    ctx->err_out->token_length = flen[1];
                }
                return false;
            }

            unsigned long ser = default_serial;
            if (flen[3] > 0) ser = strtoul(f[3], NULL, 10);
            unsigned long ref = DEFAULT_SOA_REFRESH;
            if (flen[4] > 0) ref = strtoul(f[4], NULL, 10);
            unsigned long ret = DEFAULT_SOA_RETRY;
            if (flen[5] > 0) ret = strtoul(f[5], NULL, 10);
            unsigned long exp = DEFAULT_SOA_EXPIRE;
            if (flen[6] > 0) exp = strtoul(f[6], NULL, 10);
            unsigned long min = DEFAULT_SOA_MINIMUM;
            if (flen[7] > 0) min = strtoul(f[7], NULL, 10);
            unsigned long ttl = TTL_NEGATIVE;
            if (flen[8] > 0) ttl = strtoul(f[8], NULL, 10);

            if (is_record_owned_by_zone(fqdn, target_zone, all_zones, all_zone_count)) {
                dns_record_t *soa_rec = tinydns_new_record(arena, ctx, line_start, buf, fqdn, "SOA", 6, ttl, f[9], flen[9], f[10], flen[10]);
                if (!soa_rec) return false;

                char s_ser[32], s_ref[32], s_ret[32], s_exp[32], s_min[32];
                snprintf(s_ser, sizeof(s_ser), "%lu", ser);
                snprintf(s_ref, sizeof(s_ref), "%lu", ref);
                snprintf(s_ret, sizeof(s_ret), "%lu", ret);
                snprintf(s_exp, sizeof(s_exp), "%lu", exp);
                snprintf(s_min, sizeof(s_min), "%lu", min);

                soa_rec->rdata[0] = mname;
                soa_rec->rdata[1] = rname;
                soa_rec->rdata[2] = arena_strdup(arena, s_ser);
                soa_rec->rdata[3] = arena_strdup(arena, s_ref);
                soa_rec->rdata[4] = arena_strdup(arena, s_ret);
                soa_rec->rdata[5] = arena_strdup(arena, s_exp);
                soa_rec->rdata[6] = arena_strdup(arena, s_min);
                soa_rec->rdata_count = 7;
            }
            return true;
        }

        case ':': { // 汎用レコード (:fqdn:n:rdata:ttl:timestamp:lo)
            char *fqdn = tinydns_decode_fqdn(arena, f[0], flen[0]);
            if (!fqdn) {
                if (ctx && ctx->err_out) {
                    ctx->err_out->error_message = "Invalid FQDN in tinydns generic record";
                    ctx->err_out->error_offset = (size_t)(line_start - buf);
                    ctx->err_out->token_length = flen[0];
                }
                return false;
            }

            if (flen[1] == 0) {
                if (ctx && ctx->err_out) {
                    ctx->err_out->error_message = "Missing type number in tinydns generic record";
                    ctx->err_out->error_offset = (size_t)(line_start - buf);
                    ctx->err_out->token_length = 1;
                }
                return false;
            }

            unsigned long type_num = strtoul(f[1], NULL, 10);
            // 禁止タイプ検証 (0, NS=2, CNAME=5, SOA=6, PTR=12, MX=15, AXFR=252)
            if (type_num == 0 || type_num == 2 || type_num == 5 || type_num == 6 ||
                type_num == 12 || type_num == 15 || type_num == 252 || type_num > 65535) {
                if (ctx && ctx->err_out) {
                    ctx->err_out->error_message = "Prohibited or invalid RR type in tinydns generic record";
                    ctx->err_out->error_offset = (size_t)(line_start - buf);
                    ctx->err_out->token_length = flen[1];
                }
                return false;
            }

            unsigned long ttl = TTL_POSITIVE;
            if (flen[3] > 0) ttl = strtoul(f[3], NULL, 10);

            if (is_record_owned_by_zone(fqdn, target_zone, all_zones, all_zone_count)) {
                size_t raw_len = 0;
                uint8_t *raw_bytes = tinydns_decode_bytes(arena, f[2], flen[2], &raw_len);
                if (!raw_bytes && flen[2] > 0) return false;
                if (raw_len > 65535) {
                    if (ctx && ctx->err_out) {
                        ctx->err_out->error_message = "Generic RDATA exceeds 65535 bytes";
                        ctx->err_out->error_offset = (size_t)(line_start - buf);
                        ctx->err_out->token_length = flen[2];
                    }
                    return false;
                }

                char type_buf[16];
                snprintf(type_buf, sizeof(type_buf), "TYPE%lu", type_num);

                dns_record_t *gen_rec = tinydns_new_record(arena, ctx, line_start, buf, fqdn, type_buf, (uint16_t)type_num, ttl, f[4], flen[4], f[5], flen[5]);
                if (!gen_rec) return false;
                gen_rec->generic_data = raw_bytes;
                gen_rec->generic_len = (uint16_t)raw_len;
                gen_rec->rdata_count = 0;
            }
            return true;
        }

        case '%': { // location
            if (arena->location_count >= 4096) {
                syslog(LOG_WARNING, "[tinydns] location定義が上限(4096)に達したため、"
                       "これ以上の%%行は無視します (line %lu)", linenum);
                return true;
            }
            tinydns_location_entry_t loc;
            memset(&loc, 0, sizeof(loc));
            loc.code[0] = flen[0] > 0 ? f[0][0] : 0;
            loc.code[1] = flen[0] > 1 ? f[0][1] : 0;

            uint8_t prefix[4] = {0};
            uint8_t prefix_len = 0;
            size_t pos = 0;
            while (prefix_len < 4 && pos < flen[1]) {
                unsigned long val = 0;
                size_t start = pos;
                while (pos < flen[1] && isdigit((unsigned char)f[1][pos])) {
                    val = val * 10 + (f[1][pos] - '0');
                    pos++;
                }
                if (pos == start) break;
                prefix[prefix_len++] = (uint8_t)(val & 0xFF);
                if (pos < flen[1] && f[1][pos] == '.') pos++;
                else break;
            }
            loc.prefix_len = prefix_len;
            memcpy(loc.prefix, prefix, 4);

            tinydns_location_entry_t *new_locs = realloc(arena->locations,
                (arena->location_count + 1) * sizeof(tinydns_location_entry_t));
            if (!new_locs) return false;
            arena->locations = new_locs;
            arena->locations[arena->location_count++] = loc;
            return true;
        }

        default: {
            if (ctx && ctx->err_out) {
                ctx->err_out->error_message = "Unknown tinydns record type character";
                ctx->err_out->error_offset = (size_t)(line_start - buf);
                ctx->err_out->token_length = 1;
            }
            return false;
        }
    }
}

/* ============================================================================
 * parse_tinydns_data エントリポイント
 * ============================================================================ */
int parse_tinydns_data(char *buf, size_t len, zone_arena_t *arena, parse_context_t *ctx) {
    if (!buf || !arena) return -1;
    arena->is_tinydns_format = true;

    // SOA serial 用にファイルの mtime を取得
    uint32_t default_serial = (uint32_t)time(NULL);
    if (ctx && ctx->visited_paths && ctx->visited_count > 0 && ctx->visited_paths[0]) {
        struct stat st;
        if (stat(ctx->visited_paths[0], &st) == 0) {
            default_serial = (uint32_t)st.st_mtime;
            if (default_serial == 0) default_serial = 1;
        }
    }

    size_t linestart = 0;
    unsigned long linenum = 1;
    while (linestart < len) {
        size_t lineend = linestart;
        while (lineend < len && buf[lineend] != '\n') lineend++;
        size_t linelen = lineend - linestart;
        char *line = buf + linestart;

        // セクション2: 末尾のスペース、\t、\n、\r をトリム
        // (\r は実用性向上のための意図的な KariDNS 拡張)
        while (linelen > 0) {
            char c = line[linelen - 1];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') linelen--;
            else break;
        }

        if (linelen == 0) {
            linestart = lineend + 1;
            linenum++;
            continue;
        }

        if (line[0] == '#') {
            linestart = lineend + 1;
            linenum++;
            continue;
        }

        // セクション2: 行頭が '-' の行は無効化行として無条件スキップ
        if (line[0] == '-') {
            linestart = lineend + 1;
            linenum++;
            continue;
        }

        // セクション2: 15フィールドへの colon 分割 (先頭1文字の直後から)
        char *f[TINYDNS_NUMFIELDS];
        size_t flen[TINYDNS_NUMFIELDS];
        size_t j = 1;
        for (int i = 0; i < TINYDNS_NUMFIELDS; i++) {
            if (j >= linelen) {
                f[i] = line + linelen;
                flen[i] = 0; // フィールド欠落 = 空文字列
            } else {
                char *start = line + j;
                size_t remain = linelen - j;
                size_t k = 0;
                while (k < remain && start[k] != ':') k++;
                f[i] = start;
                flen[i] = k;
                j += k + 1;
            }
        }

        if (!tinydns_process_line(arena, ctx, line, buf, line[0], f, flen, default_serial, linenum)) {
            return -1;
        }

        linestart = lineend + 1;
        linenum++;
    }

    return (int)arena->count;
}

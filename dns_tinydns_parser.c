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
#include "dns_log.h"
#include <time.h>
#include <math.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define TTL_NS 259200UL
#define TTL_POSITIVE 86400UL
#define TTL_NEGATIVE 2560UL
#define TINYDNS_NUMFIELDS 15

#define DEFAULT_SOA_REFRESH 16384UL
#define DEFAULT_SOA_RETRY   2048UL
#define DEFAULT_SOA_EXPIRE  1048576UL
#define DEFAULT_SOA_MINIMUM 2560UL

/* the error of a field of the line: err_out points at the field */
static void tinydns_field_error(parse_context_t *ctx, const char *buf, const char *field, size_t len, const char *msg) {
    if (!ctx || !ctx->err_out) return;
    ctx->err_out->error_message = msg;
    ctx->err_out->error_offset = (size_t)(field - buf);
    ctx->err_out->token_length = len;
}

/* ============================================================================
 * ゾーン振り分け・親子ゾーン重複登録防止判定
 * ============================================================================ */
static bool is_record_owned_by_zone(const char *record_name, const char *target_zone, const char **all_zones, int all_zone_count) {
    if (!record_name || !target_zone || !*target_zone) return true;

    size_t tlen = dns_name_len_no_root(target_zone, strlen(target_zone));

    // target_zone へのサフィックス一致確認 (末尾一致 + エスケープされない '.' のラベル境界)
    if (!domain_name_is_at_or_below(record_name, target_zone)) return false;

    // 親子ゾーン重複防止: all_zones の中で record_name に最長一致するゾーンを探す
    if (all_zones && all_zone_count > 0) {
        size_t longest_len = 0;
        for (int i = 0; i < all_zone_count; i++) {
            const char *z = all_zones[i];
            if (!z) continue;
            size_t zlen = dns_name_len_no_root(z, strlen(z));
            if (domain_name_is_at_or_below(record_name, z) && zlen > longest_len) {
                longest_len = zlen;
            }
        }
        if (longest_len > tlen) {
            // 他により長く一致する子ゾーンが存在するため、親ゾーン側には登録しない
            return false;
        }
    }

    return true;
}

/* is_record_owned_by_zone() に加えて、同じ view のどのゾーンにも属さない
 * レコードを数える (R-27: ゾーン外データは警告して捨てる)。'=' / '6' 行から
 * 自動生成する逆引き PTR は、逆引きゾーンを置かないのが普通なので数えない。 */
/* 次の上位の名前 ("a.example.test." -> "example.test.")。最上位のラベルなら NULL */
static const char *parent_name(const char *name) {
    const char *dot = strchr_unescaped(name, '.');
    return (dot && dot[1]) ? dot + 1 : NULL;
}

static bool tinydns_owned(parse_context_t *ctx, const char *record_name, bool count_orphan) {
    const char *target_zone = ctx ? ctx->default_origin : NULL;
    if (ctx && ctx->zone_exists && record_name && target_zone && *target_zone) {
        /* 索引で引く版。record_name から上位へたどり、target_zone より長いゾーンが
         * あればそちら (子ゾーン) のレコード。ゾーン数ではなくラベル数に比例する。 */
        if (domain_name_is_at_or_below(record_name, target_zone)) {
            size_t tlen = dns_name_len_no_root(target_zone, strlen(target_zone));
            for (const char *p = record_name; p; p = parent_name(p)) {
                if (dns_name_len_no_root(p, strlen(p)) <= tlen) break;
                if (ctx->zone_exists(ctx->zone_exists_ud, p)) return false;
            }
            return true;
        }
        if (!count_orphan) return false;
        for (const char *p = record_name; p; p = parent_name(p)) {
            if (ctx->zone_exists(ctx->zone_exists_ud, p)) return false;
        }
        if (ctx->zone_exists(ctx->zone_exists_ud, ".")) return false; /* ルートゾーン */
        if (ctx->out_of_zone_count++ == 0) ctx->first_out_of_zone = record_name;
        return false;
    }
    const char **all_zones = ctx ? ctx->all_zone_names : NULL;
    int all_zone_count = ctx ? ctx->all_zone_count : 0;
    if (is_record_owned_by_zone(record_name, target_zone, all_zones, all_zone_count)) return true;
    if (count_orphan && record_name && all_zones && all_zone_count > 0) {
        for (int i = 0; i < all_zone_count; i++) {
            if (all_zones[i] && domain_name_is_at_or_below(record_name, all_zones[i])) return false;
        }
        if (ctx->out_of_zone_count++ == 0) ctx->first_out_of_zone = record_name;
    }
    return false;
}

/* ============================================================================
 * セクション2-1(a): FQDNフィールド用デコーダ
 * ドット区切り、空ラベルは黙って読み飛ばす(先頭/末尾/連続ドット許容)、
 * \nnn(8進数、最大3桁)と \x(リテラル文字)エスケープに対応。
 * 出力は末尾ドット付きの正規形 (dns_wire.h) の文字列 ("example.com." のような形)。
 * 復号したラベルのオクテットは dns_label_to_text() で書く (\056 で得た '.' や \000 を
 * そのまま文字列に入れると、区切りや終端と区別できない)。名前全体は 255 オクテットまで
 * (RFC 1035 §2.3.4。超える名前はワイヤ形式に書けない)。
 * ============================================================================ */
static bool tinydns_flush_label(const char *label, size_t labellen, char *out, size_t out_cap,
                                size_t *outlen, size_t *wirelen) {
    *wirelen += labellen + 1;
    if (*wirelen > 255) return false; // FQDN超過 (RFC 1035 §2.3.4)
    size_t n = dns_label_to_text((const uint8_t *)label, labellen, out + *outlen, out_cap - *outlen - 2);
    if (n == (size_t)-1) return false;
    *outlen += n;
    out[(*outlen)++] = '.';
    return true;
}

static char *tinydns_decode_fqdn(zone_arena_t *arena, const char *field, size_t flen) {
    char label[64];
    size_t labellen = 0;
    char out[DNS_NAME_TEXT_SIZE];
    size_t outlen = 0;
    size_t wirelen = 1; // 終端のルートラベル
    size_t i = 0;

    while (i < flen) {
        char ch = field[i++];
        if (ch == '.') {
            if (labellen > 0) {
                if (!tinydns_flush_label(label, labellen, out, sizeof(out), &outlen, &wirelen)) return NULL;
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
        if (!tinydns_flush_label(label, labellen, out, sizeof(out), &outlen, &wirelen)) return NULL;
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
 * セクション3: IPv4 アドレス
 * review Z-4 (user decision 2026-11-22: strict, not djbdns' looseness): djbdns ip4_scan() keeps the low 8 bits of an octet and stops at the
 * first character that does not fit, so "999.1.1.1" became 231.1.1.1, "1.2.3.4junk" 1.2.3.4 and "not-an-ip" no record at all, without a
 * word.  Here a non-empty field is exactly four decimal octets 0-255 (1-3 digits) and nothing else; anything else is an error of the line,
 * and so of the file.  An empty field still means "no address" (djbdns).
 * ============================================================================ */
static bool tinydns_octet_scan(const char *s, size_t len, size_t *pos, uint8_t *out) {
    size_t start = *pos;
    unsigned val = 0;
    while (*pos < len && *pos - start < 3 && isdigit((unsigned char)s[*pos])) val = val * 10 + (unsigned)(s[(*pos)++] - '0');
    if (*pos == start || val > 255 || (*pos < len && isdigit((unsigned char)s[*pos]))) return false;
    *out = (uint8_t)val;
    return true;
}

static bool tinydns_ip4_scan(const char *s, size_t len, uint8_t ip[4]) {
    size_t pos = 0;
    for (int oct = 0; oct < 4; oct++) {
        if (oct > 0) {
            if (pos >= len || s[pos] != '.') return false;
            pos++;
        }
        if (!tinydns_octet_scan(s, len, &pos, &ip[oct])) return false;
    }
    return pos == len;
}

/* The ip field of a line: false (error set) when it is not empty and not an IPv4 address; *has = whether there is one */
static bool tinydns_ip4_field(parse_context_t *ctx, const char *buf, const char *field, size_t len, uint8_t ip[4], bool *has) {
    *has = len > 0;
    if (len == 0 || tinydns_ip4_scan(field, len, ip)) return true;
    tinydns_field_error(ctx, buf, field, len, "Invalid IPv4 address in tinydns record (expected four decimal octets 0-255, e.g. 192.0.2.1)");
    return false;
}

/* ============================================================================
 * IPv6 ヘルパー: 32文字の生16進数デコード & 逆順ニブルPTRドメイン名生成
 * ============================================================================ */
/* review Z-6: the ip6 field of a 3 / 6 line is 32 hex digits (no colons); one that was not left the AAAA and the PTRs out without a word.
 * An empty field still means "no address", as an empty ip field does. */
static bool tinydns_ip6_field(parse_context_t *ctx, const char *buf, const char *field, size_t flen, uint8_t out[16], bool *has) {
    *has = flen > 0;
    if (flen == 0) return true;
    bool ok = flen == 32;
    for (int i = 0; ok && i < 16; i++) {
        int hi = hex_char_to_val(field[i * 2]);
        int lo = hex_char_to_val(field[i * 2 + 1]);
        if (hi < 0 || lo < 0) ok = false;
        else out[i] = (uint8_t)((hi << 4) | lo);
    }
    if (!ok) tinydns_field_error(ctx, buf, field, flen, "Invalid IPv6 address in tinydns record (expected 32 hexadecimal digits without colons)");
    return ok;
}

static void tinydns_ipv6_ptr_name(const uint8_t ip6[16], char *out, size_t out_size, const char *suffix) {
    size_t pos = 0;
    for (int i = 15; i >= 0; i--) {
        pos += (size_t)snprintf(out + pos, out_size > pos ? out_size - pos : 0, "%x.%x.",
                                ip6[i] & 0x0F, (ip6[i] >> 4) & 0x0F);
    }
    snprintf(out + pos, out_size > pos ? out_size - pos : 0, "%s.", suffix);
}

#define TAI64_UNIX_EPOCH_OFFSET 4611686018427387904ULL /* 0x4000000000000000 */

/* timestampフィールド(0〜16桁の16進数)をUnix時刻へ変換する。16桁未満なら残りをゼロ埋めする (ttdparse() と同じ)。
 * パーサー内ではスキップ判定を行わず、dns_record_t に ttd を持たせてクエリ時に評価する。
 * review Z-6: ttdparse() reads a character that is not a hex digit as 0 (and ignores a 17th digit), so a mistyped time stamp became another
 * time without a word; here it is an error (false).  Upper-case digits are accepted (ttdparse() takes lower case only).  An empty field:
 * *has_ts = false. */
static bool tinydns_parse_timestamp(const char *field, size_t flen, bool *has_ts, time_t *out_unix) {
    *has_ts = false;
    *out_unix = 0;
    if (flen == 0) return true;
    if (flen > 16) return false;
    uint64_t tai64 = 0;
    for (size_t i = 0; i < 16; i++) {
        int nibble = 0;
        if (i < flen && (nibble = hex_char_to_val(field[i])) < 0) return false;
        tai64 = (tai64 << 4) | (uint64_t)nibble;
    }
    *has_ts = true;
    if (tai64 >= TAI64_UNIX_EPOCH_OFFSET) *out_unix = (time_t)(tai64 - TAI64_UNIX_EPOCH_OFFSET);   /* (before 1970: 0, 実運用ではまず起こらない) */
    return true;
}

/* ============================================================================
 * ヘルパー: 復号済みの名前 (正規形) 2 つを prefix.fqdn として連結する。
 * 復号済みの文字列を tinydns_decode_fqdn() に通し直すと、正規形の \DDD (10 進) を
 * tinydns の 8 進エスケープとして読んでしまうため、文字列のまま連結する。
 * ============================================================================ */
static char *tinydns_join_names(zone_arena_t *arena, const char *prefix, const char *fqdn) {
    if (!prefix || !fqdn) return NULL;
    size_t plen = strlen(prefix);                      // "x.ns." (末尾ドット付き)
    size_t flen = strcmp(fqdn, ".") == 0 ? 0 : strlen(fqdn);
    char joined[DNS_NAME_TEXT_SIZE];
    if (plen + flen + 1 > sizeof(joined)) return NULL;
    memcpy(joined, prefix, plen);
    memcpy(joined + plen, fqdn, flen);
    joined[plen + flen] = '\0';
    uint8_t wire[256];
    if (write_uncompressed_name_ext(wire, 0, sizeof(wire), joined, false) < 0) return NULL; // 255 オクテット超
    return arena_strdup(arena, joined);
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
        // x_len == 0 の時は ".ns." -> "ns." となり、ns.<fqdn> になる
        size_t suf_len = strlen(suffix);
        char comb[512];
        if (x_len + suf_len + 1 > sizeof(comb)) return NULL;
        if (x_len > 0) memcpy(comb, x_field, x_len);
        memcpy(comb + x_len, suffix, suf_len);
        comb[x_len + suf_len] = '\0';
        char *prefix = tinydns_decode_fqdn(arena, comb, x_len + suf_len);
        return tinydns_join_names(arena, prefix, fqdn ? fqdn : ".");
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
    bool has_ttd = false;
    time_t ttd = 0;
    if (!tinydns_parse_timestamp(ts_field, ts_len, &has_ttd, &ttd)) {
        tinydns_field_error(ctx, buf, ts_field, ts_len, "Invalid timestamp in tinydns record (expected at most 16 hexadecimal digits)");
        return NULL;
    }
    /* review Z-6: a location code is 1 or 2 characters; djbdns keeps the first 2 of a longer one, so "abc" and "abd" were one location */
    if (lo_len > 2) {
        tinydns_field_error(ctx, buf, lo_field, lo_len, "Invalid location code in tinydns record (at most 2 characters)");
        return NULL;
    }
    dns_record_t *rec = arena_alloc_record(arena, ctx, line_start, buf);
    if (!rec) return NULL;
    rec->name = owner;
    rec->type = arena_strdup(arena, type_str);
    rec->type_code = type_code;
    if (ttl > 2147483647UL) ttl = 2147483647UL; // RFC 8767 §4: BIND 形式と同じく丸める (O-14。32 bit への切り捨てもしない)
    rec->ttl_value = (uint32_t)ttl;
    rec->class_val = 1; // IN
    rec->class_str = "IN";
    char *ttl_buf = arena_alloc(arena, 16);
    if (ttl_buf) {
        snprintf(ttl_buf, 16, "%lu", ttl);
        rec->ttl = ttl_buf;
    }

    rec->tinydns_ttd = has_ttd ? ttd : 0;
    rec->tinydns_ttl_countdown = has_ttd && (ttl == 0);

    rec->tinydns_loc[0] = lo_len > 0 ? lo_field[0] : 0;
    rec->tinydns_loc[1] = lo_len > 1 ? lo_field[1] : 0;

    return rec;
}

/* D13 (review low L4 dns_tinydns_parser.c [1]): a TTL (or SOA time) field is decimal digits and nothing else.  strtoul() read "abc" as 0 and a
 * signed "-1" as a huge value; an empty field keeps the default of the line (the callers test the length first).  Larger numbers saturate
 * and are cut to 2147483647 by tinydns_new_record() (RFC 8767 s4). */
static bool tinydns_ttl_field(parse_context_t *ctx, const char *line_start, const char *buf, const char *field, size_t len, unsigned long *out) {
    bool ok = len > 0;
    for (size_t i = 0; i < len && ok; i++)
        if (!isdigit((unsigned char)field[i])) ok = false;
    if (!ok) {
        if (ctx && ctx->err_out) {
            ctx->err_out->error_message = "Invalid TTL in tinydns record (expected decimal digits only)";
            ctx->err_out->error_offset = (size_t)(line_start - buf);
            ctx->err_out->token_length = len;
        }
        return false;
    }
    *out = strtoul(field, NULL, 10);
    return true;
}

/* A numeric RDATA field (MX distance, SRV port / weight / priority, NAPTR order / preference, SSHFP algorithm / type, the type of a
 * generic ':' line): decimal digits only, at most MAX.  strtoul() read garbage as 0 and wrapped a value too large for the field. */
static bool tinydns_num_field(parse_context_t *ctx, const char *line_start, const char *buf, const char *field, size_t len,
                              unsigned long max, const char *what, unsigned long *out) {
    bool ok = len > 0 && len <= 10;
    for (size_t i = 0; i < len && ok; i++)
        if (!isdigit((unsigned char)field[i])) ok = false;
    unsigned long v = ok ? strtoul(field, NULL, 10) : 0;
    if (!ok || v > max) {
        if (ctx && ctx->err_out) {
            ctx->err_out->error_message = what;
            ctx->err_out->error_offset = (size_t)(line_start - buf);
            ctx->err_out->token_length = len;
        }
        return false;
    }
    *out = v;
    return true;
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
            if (flen[3] > 0 && !tinydns_ttl_field(ctx, line_start, buf, f[3], flen[3], &ttl)) return false;

            if (typech == '.') {
                // SOA レコード
                if (tinydns_owned(ctx, fqdn, true)) {
                    // SOA自身のTTL: f[3]が明示的に 0 (数値として。"00" も) の場合のみ 0、それ以外(省略含む)は 2560
                    unsigned long soa_ttl = TTL_NEGATIVE;
                    if (flen[3] > 0 && ttl == 0) soa_ttl = 0;

                    // rname は "\12hostmaster" + fqdn
                    char *rname = tinydns_join_names(arena, "hostmaster.", fqdn);
                    if (!rname) {
                        /* the name does not fit 255 octets: it used to become "hostmaster." (a wrong SOA RNAME) */
                        if (ctx && ctx->err_out) {
                            ctx->err_out->error_message = "Name too long: hostmaster.<zone> in tinydns '.' record does not fit 255 octets";
                            ctx->err_out->error_offset = (size_t)(line_start - buf);
                            ctx->err_out->token_length = flen[0];
                        }
                        return false;
                    }

                    dns_record_t *soa_rec = tinydns_new_record(arena, ctx, line_start, buf, fqdn, "SOA", 6, soa_ttl, f[4], flen[4], f[5], flen[5]);
                    if (!soa_rec) return false;

                    char s_ser[32], s_ref[32], s_ret[32], s_exp[32], s_min[32];
                    snprintf(s_ser, sizeof(s_ser), "%u", default_serial);
                    snprintf(s_ref, sizeof(s_ref), "%lu", DEFAULT_SOA_REFRESH);
                    snprintf(s_ret, sizeof(s_ret), "%lu", DEFAULT_SOA_RETRY);
                    snprintf(s_exp, sizeof(s_exp), "%lu", DEFAULT_SOA_EXPIRE);
                    snprintf(s_min, sizeof(s_min), "%lu", DEFAULT_SOA_MINIMUM);

                    if (!arena_record_alloc_rdata(arena, soa_rec, 7)) return false;
                    soa_rec->rdata[0] = x;
                    soa_rec->rdata[1] = rname;
                    soa_rec->rdata[2] = arena_strdup(arena, s_ser);
                    soa_rec->rdata[3] = arena_strdup(arena, s_ref);
                    soa_rec->rdata[4] = arena_strdup(arena, s_ret);
                    soa_rec->rdata[5] = arena_strdup(arena, s_exp);
                    soa_rec->rdata[6] = arena_strdup(arena, s_min);
                    soa_rec->rdata_count = 7;
                }
            }

            // NS レコード。'.' 行は SOA で数え済み: 同じ行をゾーン外として二度数えない (review low L4 [10])
            if (tinydns_owned(ctx, fqdn, typech == '&')) {
                dns_record_t *ns_rec = tinydns_new_record(arena, ctx, line_start, buf, fqdn, "NS", 2, ttl, f[4], flen[4], f[5], flen[5]);
                if (!ns_rec) return false;
                if (!arena_record_alloc_rdata(arena, ns_rec, 1)) return false;
                ns_rec->rdata[0] = x;
                ns_rec->rdata_count = 1;
            }

            // 連動 A レコード (ip有効時)
            uint8_t ip[4];
            bool has_ip;
            if (!tinydns_ip4_field(ctx, buf, f[1], flen[1], ip, &has_ip)) return false;
            if (has_ip) {
                if (tinydns_owned(ctx, x, true)) {
                    char ipstr[16];
                    snprintf(ipstr, sizeof(ipstr), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
                    dns_record_t *a_rec = tinydns_new_record(arena, ctx, line_start, buf, x, "A", 1, ttl, f[4], flen[4], f[5], flen[5]);
                    if (!a_rec) return false;
                    if (!arena_record_alloc_rdata(arena, a_rec, 1)) return false;
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
            if (flen[2] > 0 && !tinydns_ttl_field(ctx, line_start, buf, f[2], flen[2], &ttl)) return false;

            uint8_t ip[4];
            bool has_ip;
            if (!tinydns_ip4_field(ctx, buf, f[1], flen[1], ip, &has_ip)) return false;
            if (has_ip) {
                // A レコード生成
                if (tinydns_owned(ctx, owner, true)) {
                    char ipstr[16];
                    snprintf(ipstr, sizeof(ipstr), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
                    dns_record_t *a_rec = tinydns_new_record(arena, ctx, line_start, buf, owner, "A", 1, ttl, f[3], flen[3], f[4], flen[4]);
                    if (!a_rec) return false;
                    if (!arena_record_alloc_rdata(arena, a_rec, 1)) return false;
                    a_rec->rdata[0] = arena_strdup(arena, ipstr);
                    a_rec->rdata_count = 1;
                }

                // PTR レコード生成 ('=' の場合のみ)
                if (typech == '=') {
                    char ptr_name[64];
                    snprintf(ptr_name, sizeof(ptr_name), "%u.%u.%u.%u.in-addr.arpa.", ip[3], ip[2], ip[1], ip[0]);
                    if (tinydns_owned(ctx, ptr_name, false)) {
                        dns_record_t *ptr_rec = tinydns_new_record(arena, ctx, line_start, buf,
                                                                   arena_strdup(arena, ptr_name),
                                                                   "PTR", 12, ttl, f[3], flen[3], f[4], flen[4]);
                        if (!ptr_rec) return false;
                        if (!arena_record_alloc_rdata(arena, ptr_rec, 1)) return false;
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
            if (flen[3] > 0 && !tinydns_num_field(ctx, line_start, buf, f[3], flen[3], 65535, "Invalid MX distance in tinydns record (expected 0-65535)", &dist))
                return false;

            unsigned long ttl = TTL_POSITIVE;
            if (flen[4] > 0 && !tinydns_ttl_field(ctx, line_start, buf, f[4], flen[4], &ttl)) return false;

            if (tinydns_owned(ctx, fqdn, true)) {
                dns_record_t *mx_rec = tinydns_new_record(arena, ctx, line_start, buf, fqdn, "MX", 15, ttl, f[5], flen[5], f[6], flen[6]);
                if (!mx_rec) return false;
                char dist_str[16];
                snprintf(dist_str, sizeof(dist_str), "%lu", dist);
                if (!arena_record_alloc_rdata(arena, mx_rec, 2)) return false;
                mx_rec->rdata[0] = arena_strdup(arena, dist_str);
                mx_rec->rdata[1] = x;
                mx_rec->rdata_count = 2;
            }

            // 連動 A レコード (ip有効時)
            uint8_t ip[4];
            bool has_ip;
            if (!tinydns_ip4_field(ctx, buf, f[1], flen[1], ip, &has_ip)) return false;
            if (has_ip) {
                if (tinydns_owned(ctx, x, true)) {
                    char ipstr[16];
                    snprintf(ipstr, sizeof(ipstr), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
                    dns_record_t *a_rec = tinydns_new_record(arena, ctx, line_start, buf, x, "A", 1, ttl, f[5], flen[5], f[6], flen[6]);
                    if (!a_rec) return false;
                    if (!arena_record_alloc_rdata(arena, a_rec, 1)) return false;
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
            if (flen[2] > 0 && !tinydns_ttl_field(ctx, line_start, buf, f[2], flen[2], &ttl)) return false;

            if (tinydns_owned(ctx, fqdn, true)) {
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
                    if (!arena_record_alloc_rdata(arena, txt_rec, 1)) return false;
                    txt_rec->rdata[0] = arena_strdup(arena, "");
                    txt_rec->rdata_count = 1;
                } else if (memchr(raw_bytes, 0, raw_len)) {
                    /* review low L4 dns_tinydns_parser.c [3]: a NUL octet (\000) ends a chunk that is a C string, and tinydns keeps it.
                     * The RDATA goes in as the octets of the RFC 3597 form instead (the same as a long TXT of a zone file), cut into the
                     * same 127-octet <character-string>s: at most 6096 octets of data, so the whole fits RDLENGTH */
                    size_t nchunks = (raw_len + 126) / 127;
                    uint8_t *blob = (uint8_t *)arena_alloc(arena, raw_len + nchunks);
                    if (!blob) return false;
                    size_t w = 0;
                    for (size_t offset = 0; offset < raw_len; offset += 127) {
                        size_t clen = raw_len - offset > 127 ? 127 : raw_len - offset;
                        blob[w++] = (uint8_t)clen;
                        memcpy(blob + w, raw_bytes + offset, clen);
                        w += clen;
                    }
                    txt_rec->generic_data = blob;
                    txt_rec->generic_len = (uint16_t)w;
                    txt_rec->rdata_count = 0;
                } else {
                    size_t offset = 0;
                    int chunk_idx = 0;
                    int nchunks = (int)((raw_len + 126) / 127);
                    if (nchunks > MAX_RDATA) nchunks = MAX_RDATA;
                    if (!arena_record_alloc_rdata(arena, txt_rec, nchunks)) return false;
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
            if (flen[2] > 0 && !tinydns_ttl_field(ctx, line_start, buf, f[2], flen[2], &ttl)) return false;

            if (tinydns_owned(ctx, fqdn, true)) {
                const char *tname = (typech == 'C') ? "CNAME" : "PTR";
                uint16_t tcode = (typech == 'C') ? 5 : 12;
                dns_record_t *rec = tinydns_new_record(arena, ctx, line_start, buf, fqdn, tname, tcode, ttl, f[3], flen[3], f[4], flen[4]);
                if (!rec) return false;
                if (!arena_record_alloc_rdata(arena, rec, 1)) return false;
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
            if (flen[3] > 0) {
                /* the serial is a plain number up to 4294967295, as in a BIND SOA (parse_soa_serial_strict); strtoul read "abc" as 0 and
                 * let a value above 32 bits through.  Empty still means the data file's time stamp (tinydns-data). */
                char sbuf[64];
                uint32_t sv;
                int serr;
                bool ok = flen[3] < sizeof(sbuf);
                if (ok) {
                    memcpy(sbuf, f[3], flen[3]);
                    sbuf[flen[3]] = '\0';
                    ok = parse_soa_serial_strict(sbuf, &sv, &serr);
                } else {
                    serr = 2;
                }
                if (!ok) {
                    if (ctx && ctx->err_out) {
                        ctx->err_out->error_message = serr == 2 ? "SOA serial out of range (expected 0-4294967295)"
                                                                : "Invalid SOA serial (expected a number 0-4294967295)";
                        ctx->err_out->error_offset = (size_t)(f[3] - buf);
                        ctx->err_out->token_length = flen[3];
                    }
                    return false;
                }
                ser = sv;
            }
            unsigned long ref = DEFAULT_SOA_REFRESH;
            if (flen[4] > 0 && !tinydns_ttl_field(ctx, line_start, buf, f[4], flen[4], &ref)) return false;
            unsigned long ret = DEFAULT_SOA_RETRY;
            if (flen[5] > 0 && !tinydns_ttl_field(ctx, line_start, buf, f[5], flen[5], &ret)) return false;
            unsigned long exp = DEFAULT_SOA_EXPIRE;
            if (flen[6] > 0 && !tinydns_ttl_field(ctx, line_start, buf, f[6], flen[6], &exp)) return false;
            unsigned long min = DEFAULT_SOA_MINIMUM;
            if (flen[7] > 0 && !tinydns_ttl_field(ctx, line_start, buf, f[7], flen[7], &min)) return false;
            unsigned long ttl = TTL_NEGATIVE;
            if (flen[8] > 0 && !tinydns_ttl_field(ctx, line_start, buf, f[8], flen[8], &ttl)) return false;

            if (tinydns_owned(ctx, fqdn, true)) {
                dns_record_t *soa_rec = tinydns_new_record(arena, ctx, line_start, buf, fqdn, "SOA", 6, ttl, f[9], flen[9], f[10], flen[10]);
                if (!soa_rec) return false;

                char s_ser[32], s_ref[32], s_ret[32], s_exp[32], s_min[32];
                snprintf(s_ser, sizeof(s_ser), "%lu", ser);
                snprintf(s_ref, sizeof(s_ref), "%lu", ref);
                snprintf(s_ret, sizeof(s_ret), "%lu", ret);
                snprintf(s_exp, sizeof(s_exp), "%lu", exp);
                snprintf(s_min, sizeof(s_min), "%lu", min);

                if (!arena_record_alloc_rdata(arena, soa_rec, 7)) return false;
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

            unsigned long type_num = 0;
            if (!tinydns_num_field(ctx, line_start, buf, f[1], flen[1], 65535, "Prohibited or invalid RR type in tinydns generic record (expected a number from 1 to 65535)", &type_num))
                return false;
            // 禁止タイプ検証 (0, NS=2, CNAME=5, SOA=6, PTR=12, MX=15) and every meta-type (OPT, TKEY, TSIG, IXFR, AXFR,
            // MAILB/MAILA, ANY, NXNAME): the same is_meta_rrtype() the master-file parser uses, so a meta-type can not be
            // smuggled into zone data through a generic record.
            if (type_num == 0 || type_num == 2 || type_num == 5 || type_num == 6 ||
                type_num == 12 || type_num == 15 || type_num > 65535 ||
                is_meta_rrtype((uint16_t)type_num)) {
                if (ctx && ctx->err_out) {
                    ctx->err_out->error_message = "Prohibited or invalid RR type in tinydns generic record";
                    ctx->err_out->error_offset = (size_t)(line_start - buf);
                    ctx->err_out->token_length = flen[1];
                }
                return false;
            }

            unsigned long ttl = TTL_POSITIVE;
            if (flen[3] > 0 && !tinydns_ttl_field(ctx, line_start, buf, f[3], flen[3], &ttl)) return false;

            if (tinydns_owned(ctx, fqdn, true)) {
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
                /* D15-2, as for "\# <len> <hex>" in a master file: the RDATA of a type the server knows must be valid for that type
                 * (dns_generic_rdata_check(); an unknown type is any octets).  Before this, a malformed known-type RDATA was served as it was. */
                const char *gwhy = dns_generic_rdata_check((uint16_t)type_num, raw_bytes ? raw_bytes : (const uint8_t *)"", raw_len);
                if (gwhy) {
                    if (ctx && ctx->err_out) {
                        ctx->err_out->error_message = gwhy;
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

        case '3':   // AAAA のみ (3fqdn:ip6:ttl:timestamp:lo)
        case '6': { // AAAA + PTR (6fqdn:ip6:ttl:timestamp:lo)
            char *owner = tinydns_decode_fqdn(arena, f[0], flen[0]);
            if (!owner) {
                if (ctx && ctx->err_out) {
                    ctx->err_out->error_message = "Invalid FQDN in tinydns 3/6 record";
                    ctx->err_out->error_offset = (size_t)(line_start - buf);
                    ctx->err_out->token_length = flen[0];
                }
                return false;
            }

            unsigned long ttl = TTL_POSITIVE;
            if (flen[2] > 0 && !tinydns_ttl_field(ctx, line_start, buf, f[2], flen[2], &ttl)) return false;

            uint8_t ip6[16];
            bool has_ip6;
            if (!tinydns_ip6_field(ctx, buf, f[1], flen[1], ip6, &has_ip6)) return false;
            if (has_ip6) {
                if (tinydns_owned(ctx, owner, true)) {
                    struct in6_addr addr;
                    memcpy(&addr, ip6, 16);
                    char ip6str[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &addr, ip6str, sizeof(ip6str));
                    dns_record_t *aaaa_rec = tinydns_new_record(arena, ctx, line_start, buf, owner,
                                                                 "AAAA", 28, ttl, f[3], flen[3], f[4], flen[4]);
                    if (!aaaa_rec) return false;
                    if (!arena_record_alloc_rdata(arena, aaaa_rec, 1)) return false;
                    aaaa_rec->rdata[0] = arena_strdup(arena, ip6str);
                    aaaa_rec->rdata_count = 1;
                }

                if (typech == '6') {
                    char ptr_name_arpa[96];
                    tinydns_ipv6_ptr_name(ip6, ptr_name_arpa, sizeof(ptr_name_arpa), "ip6.arpa");
                    if (tinydns_owned(ctx, ptr_name_arpa, false)) {
                        dns_record_t *ptr_rec = tinydns_new_record(arena, ctx, line_start, buf,
                                                                    arena_strdup(arena, ptr_name_arpa),
                                                                    "PTR", 12, ttl, f[3], flen[3], f[4], flen[4]);
                        if (!ptr_rec) return false;
                        if (!arena_record_alloc_rdata(arena, ptr_rec, 1)) return false;
                        ptr_rec->rdata[0] = owner;
                        ptr_rec->rdata_count = 1;
                    }

                    char ptr_name_int[96];
                    tinydns_ipv6_ptr_name(ip6, ptr_name_int, sizeof(ptr_name_int), "ip6.int");
                    if (tinydns_owned(ctx, ptr_name_int, false)) {
                        dns_record_t *ptr_rec2 = tinydns_new_record(arena, ctx, line_start, buf,
                                                                     arena_strdup(arena, ptr_name_int),
                                                                     "PTR", 12, ttl, f[3], flen[3], f[4], flen[4]);
                        if (!ptr_rec2) return false;
                        if (!arena_record_alloc_rdata(arena, ptr_rec2, 1)) return false;
                        ptr_rec2->rdata[0] = owner;
                        ptr_rec2->rdata_count = 1;
                    }
                }
            }
            return true;
        }

        case 'S': { // SRV (Sfqdn:ip:x:port:weight:priority:ttl:timestamp:lo)
            char *owner = tinydns_decode_fqdn(arena, f[0], flen[0]);
            if (!owner) {
                if (ctx && ctx->err_out) {
                    ctx->err_out->error_message = "Invalid FQDN in tinydns S record";
                    ctx->err_out->error_offset = (size_t)(line_start - buf);
                    ctx->err_out->token_length = flen[0];
                }
                return false;
            }

            unsigned long port = 0, weight = 0, priority = 0, ttl = TTL_POSITIVE;
            if ((flen[3] > 0 && !tinydns_num_field(ctx, line_start, buf, f[3], flen[3], 65535, "Invalid SRV port in tinydns record (expected 0-65535)", &port)) ||
                (flen[4] > 0 && !tinydns_num_field(ctx, line_start, buf, f[4], flen[4], 65535, "Invalid SRV weight in tinydns record (expected 0-65535)", &weight)) ||
                (flen[5] > 0 && !tinydns_num_field(ctx, line_start, buf, f[5], flen[5], 65535, "Invalid SRV priority in tinydns record (expected 0-65535)", &priority)))
                return false;
            if (flen[6] > 0 && !tinydns_ttl_field(ctx, line_start, buf, f[6], flen[6], &ttl)) return false;

            char *target = tinydns_decode_fqdn(arena, f[2], flen[2]);
            if (!target) {
                if (ctx && ctx->err_out) {
                    ctx->err_out->error_message = "Invalid target FQDN in tinydns S record";
                    ctx->err_out->error_offset = (size_t)(line_start - buf);
                    ctx->err_out->token_length = flen[2];
                }
                return false;
            }

            uint8_t ip[4];
            bool has_ip;
            if (!tinydns_ip4_field(ctx, buf, f[1], flen[1], ip, &has_ip)) return false;
            if (has_ip) {
                if (tinydns_owned(ctx, target, true)) {
                    char ipstr[16];
                    snprintf(ipstr, sizeof(ipstr), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
                    dns_record_t *a_rec = tinydns_new_record(arena, ctx, line_start, buf, target,
                                                             "A", 1, ttl, f[7], flen[7], f[8], flen[8]);
                    if (!a_rec) return false;
                    if (!arena_record_alloc_rdata(arena, a_rec, 1)) return false;
                    a_rec->rdata[0] = arena_strdup(arena, ipstr);
                    a_rec->rdata_count = 1;
                }
            }

            if (tinydns_owned(ctx, owner, true)) {
                dns_record_t *srv_rec = tinydns_new_record(arena, ctx, line_start, buf, owner,
                                                           "SRV", 33, ttl, f[7], flen[7], f[8], flen[8]);
                if (!srv_rec) return false;
                char priobuf[16], weightbuf[16], portbuf[16];
                snprintf(priobuf, sizeof(priobuf), "%lu", priority);
                snprintf(weightbuf, sizeof(weightbuf), "%lu", weight);
                snprintf(portbuf, sizeof(portbuf), "%lu", port);

                if (!arena_record_alloc_rdata(arena, srv_rec, 4)) return false;
                srv_rec->rdata[0] = arena_strdup(arena, priobuf);
                srv_rec->rdata[1] = arena_strdup(arena, weightbuf);
                srv_rec->rdata[2] = arena_strdup(arena, portbuf);
                srv_rec->rdata[3] = target;
                srv_rec->rdata_count = 4;
            }
            return true;
        }

        case 'N': { // NAPTR (Nfqdn:order:pref:flags:service:regexp:replacement:ttl:timestamp:lo)
            char *owner = tinydns_decode_fqdn(arena, f[0], flen[0]);
            if (!owner) {
                if (ctx && ctx->err_out) {
                    ctx->err_out->error_message = "Invalid FQDN in tinydns N record";
                    ctx->err_out->error_offset = (size_t)(line_start - buf);
                    ctx->err_out->token_length = flen[0];
                }
                return false;
            }

            unsigned long order = 0, pref = 0, ttl = TTL_POSITIVE;
            if ((flen[1] > 0 && !tinydns_num_field(ctx, line_start, buf, f[1], flen[1], 65535, "Invalid NAPTR order in tinydns record (expected 0-65535)", &order)) ||
                (flen[2] > 0 && !tinydns_num_field(ctx, line_start, buf, f[2], flen[2], 65535, "Invalid NAPTR preference in tinydns record (expected 0-65535)", &pref)))
                return false;
            if (flen[7] > 0 && !tinydns_ttl_field(ctx, line_start, buf, f[7], flen[7], &ttl)) return false;

            if (tinydns_owned(ctx, owner, true)) {
                size_t flags_len = 0, service_len = 0, regexp_len = 0;
                uint8_t *flags_bytes = tinydns_decode_bytes(arena, f[3], flen[3], &flags_len);
                uint8_t *service_bytes = tinydns_decode_bytes(arena, f[4], flen[4], &service_len);
                uint8_t *regexp_bytes = tinydns_decode_bytes(arena, f[5], flen[5], &regexp_len);
                if ((!flags_bytes && flen[3] > 0) ||
                    (!service_bytes && flen[4] > 0) ||
                    (!regexp_bytes && flen[5] > 0)) return false;
                /* review Z-6: each is one <character-string> (RFC 3403 s4.1), kept as a C string: a \000 cut it there without a word, and one
                 * longer than 255 octets cannot be written (RFC 1035 s3.3) */
                const uint8_t *nstr[3] = { flags_bytes, service_bytes, regexp_bytes };
                const size_t nlen[3] = { flags_len, service_len, regexp_len };
                for (int s = 0; s < 3; s++)
                    if (nlen[s] > 255 || (nlen[s] > 0 && memchr(nstr[s], 0, nlen[s]))) {
                        tinydns_field_error(ctx, buf, f[3 + s], flen[3 + s], "Invalid NAPTR flags, service or regexp in tinydns record "
                                            "(a NUL octet \\000, or longer than 255 octets)");
                        return false;
                    }

                char *replacement = tinydns_decode_fqdn(arena, f[6], flen[6]);
                if (!replacement) {
                    if (ctx && ctx->err_out) {
                        ctx->err_out->error_message = "Invalid replacement FQDN in tinydns N record";
                        ctx->err_out->error_offset = (size_t)(line_start - buf);
                        ctx->err_out->token_length = flen[6];
                    }
                    return false;
                }

                dns_record_t *naptr_rec = tinydns_new_record(arena, ctx, line_start, buf, owner,
                                                             "NAPTR", 35, ttl, f[8], flen[8], f[9], flen[9]);
                if (!naptr_rec) return false;

                char orderbuf[16], prefbuf[16];
                snprintf(orderbuf, sizeof(orderbuf), "%lu", order);
                snprintf(prefbuf, sizeof(prefbuf), "%lu", pref);

                if (!arena_record_alloc_rdata(arena, naptr_rec, 6)) return false;
                naptr_rec->rdata[0] = arena_strdup(arena, orderbuf);
                naptr_rec->rdata[1] = arena_strdup(arena, prefbuf);
                naptr_rec->rdata[2] = flags_bytes ? (char *)flags_bytes : arena_strdup(arena, "");
                naptr_rec->rdata[3] = service_bytes ? (char *)service_bytes : arena_strdup(arena, "");
                naptr_rec->rdata[4] = regexp_bytes ? (char *)regexp_bytes : arena_strdup(arena, "");
                naptr_rec->rdata[5] = replacement;
                naptr_rec->rdata_count = 6;
            }
            return true;
        }

        case '_': { // SSHFP (_fqdn:algorithm:fp_type:fingerprint:ttl:timestamp:lo)
            char *owner = tinydns_decode_fqdn(arena, f[0], flen[0]);
            if (!owner) {
                if (ctx && ctx->err_out) {
                    ctx->err_out->error_message = "Invalid FQDN in tinydns _ record";
                    ctx->err_out->error_offset = (size_t)(line_start - buf);
                    ctx->err_out->token_length = flen[0];
                }
                return false;
            }

            unsigned long alg = 0, fptype = 0, ttl = TTL_POSITIVE;
            if ((flen[1] > 0 && !tinydns_num_field(ctx, line_start, buf, f[1], flen[1], 255, "Invalid SSHFP algorithm in tinydns record (expected 0-255)", &alg)) ||
                (flen[2] > 0 && !tinydns_num_field(ctx, line_start, buf, f[2], flen[2], 255, "Invalid SSHFP fingerprint type in tinydns record (expected 0-255)", &fptype)))
                return false;
            if (flen[4] > 0 && !tinydns_ttl_field(ctx, line_start, buf, f[4], flen[4], &ttl)) return false;

            if (tinydns_owned(ctx, owner, true)) {
                char *fp_hex = (char *)arena_alloc(arena, flen[3] + 1);
                if (!fp_hex) return false;
                memcpy(fp_hex, f[3], flen[3]);
                fp_hex[flen[3]] = '\0';

                /* review Z-6: the fingerprint is hexadecimal, an even number of digits (RFC 4255 s3.2); a line with another one used to be
                 * left out (only karicheck warned), and one of more than 64 octets as well.  Now it is an error of the line. */
                bool fp_ok = flen[3] % 2 == 0 && flen[3] <= 2 * 65000;
                for (size_t k = 0; fp_ok && k < flen[3]; k++)
                    if (hex_char_to_val(fp_hex[k]) < 0) fp_ok = false;
                if (!fp_ok) {
                    tinydns_field_error(ctx, buf, f[3], flen[3], "Invalid SSHFP fingerprint in tinydns record (expected an even number of "
                                        "hexadecimal digits)");
                    return false;
                }

                dns_record_t *sshfp_rec = tinydns_new_record(arena, ctx, line_start, buf, owner,
                                                             "SSHFP", 44, ttl, f[5], flen[5], f[6], flen[6]);
                if (!sshfp_rec) return false;

                char alg_buf[16], fptype_buf[16];
                snprintf(alg_buf, sizeof(alg_buf), "%lu", alg);
                snprintf(fptype_buf, sizeof(fptype_buf), "%lu", fptype);

                if (!arena_record_alloc_rdata(arena, sshfp_rec, 3)) return false;
                sshfp_rec->rdata[0] = arena_strdup(arena, alg_buf);
                sshfp_rec->rdata[1] = arena_strdup(arena, fptype_buf);
                sshfp_rec->rdata[2] = fp_hex;
                sshfp_rec->rdata_count = 3;
            }
            return true;
        }

        case '%': { // location
            if (arena->location_count >= 4096) {
                /* D14 (review low L4 dns_tinydns_parser.c [15]): fail closed.  A location line that is dropped changes who gets which
                 * answer, and the load used to succeed with a partial map */
                /* log only: the caller reports err_out (zone.syntax) */
                syslog(LOG_ERR, "[tinydns] more than 4096 location (%%) lines (line %lu): the data file is refused", linenum);
                if (ctx && ctx->err_out) {
                    ctx->err_out->error_message = "Too many location lines (more than 4096 '%' lines)";
                    ctx->err_out->error_offset = (size_t)(line_start - buf);
                    ctx->err_out->token_length = flen[0];
                }
                return false;
            }
            if (flen[0] > 2) {   /* review Z-6: as the lo field of a record */
                tinydns_field_error(ctx, buf, f[0], flen[0], "Invalid location code in tinydns % line (at most 2 characters)");
                return false;
            }
            tinydns_location_entry_t loc;
            memset(&loc, 0, sizeof(loc));
            loc.code[0] = flen[0] > 0 ? f[0][0] : 0;
            loc.code[1] = flen[0] > 1 ? f[0][1] : 0;

            /* review Z-4: up to four decimal octets 0-255 separated by dots (djbdns kept the low 8 bits of an octet and ignored what
             * followed the prefix); then nothing, or the "/n" below */
            uint8_t prefix[4] = {0};
            uint8_t octets = 0;
            size_t pos = 0;
            while (octets < 4 && pos < flen[1] && f[1][pos] != '/') {
                if (!tinydns_octet_scan(f[1], flen[1], &pos, &prefix[octets])) {
                    tinydns_field_error(ctx, buf, f[1], flen[1], "Invalid IPv4 prefix in tinydns % line (expected decimal octets 0-255)");
                    return false;
                }
                octets++;
                if (pos < flen[1] && f[1][pos] == '.') pos++;
                else break;
            }
            if (pos < flen[1] && f[1][pos] != '/') {
                tinydns_field_error(ctx, buf, f[1], flen[1], "Invalid IPv4 prefix in tinydns % line (expected decimal octets 0-255)");
                return false;
            }
            // djbdns の接頭辞長はオクテット数 x 8。KariDNS 拡張として "/n" (0..32) を CIDR 長として受け付ける。
            // 以前は "/n" を黙って無視していたため "10.0.0.0/8" が /32 として扱われていた。
            unsigned int bits = (unsigned int)octets * 8;
            if (pos < flen[1] && f[1][pos] == '/') {
                pos++;
                size_t dstart = pos;
                unsigned long b = 0;
                while (pos < flen[1] && isdigit((unsigned char)f[1][pos])) {
                    if (b <= 32) b = b * 10 + (f[1][pos] - '0');
                    pos++;
                }
                if (pos == dstart || pos != flen[1] || b > 32) {
                    if (ctx && ctx->err_out) {
                        ctx->err_out->error_message = "Invalid location prefix length (expected /0 to /32)";
                        ctx->err_out->error_offset = (size_t)(line_start - buf);
                        ctx->err_out->token_length = 1;
                    }
                    return false;
                }
                bits = (unsigned int)b;
            }
            // ネットワーク部だけを残す (10.1.2.3/8 -> 10.0.0.0/8)
            for (unsigned int i = 0; i < 4; i++) {
                unsigned int keep = (bits >= (i + 1) * 8) ? 8 : (bits > i * 8 ? bits - i * 8 : 0);
                prefix[i] &= (uint8_t)(keep == 0 ? 0 : (0xFFu << (8 - keep)));
            }
            loc.prefix_bits = (uint8_t)bits;
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
    if (zone_text_has_nul(buf, len, ctx)) return -1;   /* review Z-2: as parse_zone_fast() */
    arena->is_tinydns_format = true;

    // SOA serial はデータファイルの mtime (tinydns-data と同じ)。mtime は呼び出し側が開いた fd から
    // 渡す (X-13: Capsicum の中の再読み込みでパスを stat するとバックエンドが TRAP_CAP で止まる)。
    uint32_t default_serial = (uint32_t)time(NULL);
    if (ctx && ctx->source_mtime > 0) {
        default_serial = (uint32_t)ctx->source_mtime;
        if (default_serial == 0) default_serial = 1;
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

    for (size_t i = 0; i < arena->count; i++) {
        dns_record_preparse_cache(arena, &arena->records[i]);
    }

    return (int)arena->count;
}

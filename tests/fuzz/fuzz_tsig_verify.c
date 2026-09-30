#include <time.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../../dns_wire.h"


static int initial_check_done = 0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!initial_check_done) {
        initial_check_done = 1;

        // 63バイト以下の複数ラベルで構成された、wireフォーマットでほぼ最大長(250バイト超)の
        // 有効なドメイン名。単一ラベルの上限(63バイト)を超えないよう複数ラベルに分割している点が重要。
        static const char long_name[] =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb."
            "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc."
            "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

        tsig_key_t key;
        memset(&key, 0, sizeof(key));
        key.name = (char *)long_name;
        key.algorithm = (char *)long_name; // アルゴリズム名も同様に最大長級にして worst case を再現
        key.secret_decoded_len = 32;
        memcpy(key.secret_decoded, "12345678901234567890123456789012", 32);

        uint8_t pkt[600];
        memset(pkt, 0, sizeof(pkt));
        pkt[10] = 0; pkt[11] = 1; // ARCOUNT = 1 (TSIG RRのみ)

        size_t off = 12;
        pkt[off++] = 0; // TSIG RRのオーナー名 (root)
        pkt[off++] = 0; pkt[off++] = 250; // TYPE = TSIG(250)
        pkt[off++] = 0; pkt[off++] = 255; // CLASS = ANY(255)
        pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; // TTL = 0
        size_t rdlen_pos = off; off += 2; // RDLENGTH placeholder

        size_t rdata_start = off;
        pkt[off++] = 0; // RDATA内のAlgorithm Name (wire上はroot; 検証対象の脆弱性は
                         // key->algorithm 文字列側の長さに起因するため、wire上の値自体は無関係)

        // Time Signed に実行時の現在時刻を設定し、BADTIME判定を通過させる
        uint64_t now = (uint64_t)time(NULL);
        pkt[off++] = (now >> 40) & 0xFF; pkt[off++] = (now >> 32) & 0xFF;
        pkt[off++] = (now >> 24) & 0xFF; pkt[off++] = (now >> 16) & 0xFF;
        pkt[off++] = (now >> 8) & 0xFF;  pkt[off++] = now & 0xFF;
        pkt[off++] = (300 >> 8) & 0xFF; pkt[off++] = 300 & 0xFF; // Fudge = 300秒

        pkt[off++] = 0; pkt[off++] = 0; // MAC Size = 0
        pkt[off++] = 0; pkt[off++] = 0; // Original ID
        pkt[off++] = 0; pkt[off++] = 0; // Error
        pkt[off++] = 0; pkt[off++] = 0; // Other Len = 0

        size_t rdlen = off - rdata_start;
        pkt[rdlen_pos]     = (rdlen >> 8) & 0xFF;
        pkt[rdlen_pos + 1] = rdlen & 0xFF;

        uint8_t mac_out[64]; /* >= EVP_MAX_MD_SIZE */
        static_assert(sizeof(mac_out) >= 64, "mac_out must be >= EVP_MAX_MD_SIZE (64)");
        size_t mac_len_out = 0;
        // 修正前のコードではここでASanがheap-buffer-overflowを検出する
        // (dns_wire.c内、Time Signed/Fudgeをpre_macへmemcpyする箇所)。
        // 修正後は安全に完走する。
        tsig_verify_packet(pkt, off, &key, NULL, 0, NULL, 0, false, mac_out, &mac_len_out);
    }

    if (size < 10) return 0;


    size_t key_len = data[0];
    size_t alg_len = data[1];
    if (key_len + alg_len + 4 > size) return 0;

    char key_name[256] = {0};
    char alg_name[256] = {0};
    size_t copy_k = key_len > 255 ? 255 : key_len;
    memcpy(key_name, data + 2, copy_k);
    size_t copy_a = alg_len > 255 ? 255 : alg_len;
    memcpy(alg_name, data + 2 + copy_k, copy_a);

    tsig_key_t key;
    memset(&key, 0, sizeof(key));
    key.name = key_name;
    key.algorithm = alg_name;
    key.secret_decoded_len = 32;
    memcpy(key.secret_decoded, "12345678901234567890123456789012", 32);
    key.next = NULL;

    // 残りのバイト列を「受信した(攻撃者制御下の)パケット」として渡す
    size_t pkt_off = 2 + copy_k + copy_a;
    if (pkt_off >= size) return 0;
    const uint8_t *pkt = data + pkt_off;
    size_t pkt_len = size - pkt_off;
    if (pkt_len < 12) return 0;

    uint8_t mac_out[64]; /* >= EVP_MAX_MD_SIZE */
    static_assert(sizeof(mac_out) >= 64, "mac_out must be >= EVP_MAX_MD_SIZE (64)");
    size_t mac_len_out = 0;
    tsig_verify_packet(pkt, pkt_len, &key, NULL, 0, NULL, 0, false, mac_out, &mac_len_out);

    /* tsig_parse_rr() と、鍵名・アルゴリズムが一致したときの MAC 計算と時刻/切り詰めの判定
     * (要求の検証と、要求の MAC を渡す応答の検証の両方) */
    tsig_rr_t rr;
    if (tsig_parse_rr(pkt, pkt_len, &rr) == 1) {
        tsig_key_t same;
        memset(&same, 0, sizeof(same));
        same.name = rr.key_name;
        same.algorithm = rr.alg_name;
        same.secret_decoded_len = 32;
        memcpy(same.secret_decoded, "12345678901234567890123456789012", 32);
        tsig_verify_info_t info;
        static const uint8_t req_mac[32] = { 1 };
        tsig_verify_packet_ex(pkt, pkt_len, &same, NULL, 0, NULL, 0, false, mac_out, &mac_len_out, &info);
        tsig_verify_packet_ex(pkt, pkt_len, &same, req_mac, sizeof(req_mac), NULL, 0, false, mac_out, &mac_len_out, &info);
    }

    return 0;
}

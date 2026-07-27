#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "../../dns_wire.h"


static int initial_check_done = 0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!initial_check_done) {
        initial_check_done = 1;
        
        // 253 byte key and alg names to test fix 1
        char long_name[255];
        memset(long_name, 'a', 250);
        long_name[250] = '.';
        long_name[251] = 'c';
        long_name[252] = 'o';
        long_name[253] = 'm';
        long_name[254] = '\0';
        
        tsig_key_t key;
        memset(&key, 0, sizeof(key));
        key.name = long_name;
        key.algorithm = long_name;
        key.secret_decoded_len = 32;
        memcpy(key.secret_decoded, "12345678901234567890123456789012", 32);
        
        // Dummy packet
        uint8_t pkt[512];
        memset(pkt, 0, sizeof(pkt));
        // Header
        pkt[4] = 0; pkt[5] = 0; // qdcount
        pkt[6] = 0; pkt[7] = 0; // ancount
        pkt[8] = 0; pkt[9] = 0; // nscount
        pkt[10] = 0; pkt[11] = 1; // arcount = 1
        
        // one TSIG RR
        // Name (root)
        size_t off = 12;
        pkt[off++] = 0; 
        // Type TSIG (250)
        pkt[off++] = 0; pkt[off++] = 250;
        // Class ANY (255)
        pkt[off++] = 0; pkt[off++] = 255;
        // TTL (0)
        pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 0;
        // RDLENGTH 
        pkt[off++] = 0; pkt[off++] = 26; // dummy length
        // Alg Name (root)
        pkt[off++] = 0;
        // Time Signed
        off += 6;
        // Fudge
        pkt[off++] = 1; pkt[off++] = 0; // 256
        // MAC size
        pkt[off++] = 0; pkt[off++] = 0;
        // Orig ID
        pkt[off++] = 0; pkt[off++] = 0;
        // Error
        pkt[off++] = 0; pkt[off++] = 0;
        // Other Len
        pkt[off++] = 0; pkt[off++] = 0;
        
        uint8_t mac_out[64];
        size_t mac_len_out = 0;
        tsig_verify_packet(pkt, off, &key, mac_out, &mac_len_out);
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

    uint8_t mac_out[64];
    size_t mac_len_out = 0;
    tsig_verify_packet(pkt, pkt_len, &key, mac_out, &mac_len_out);

    return 0;
}

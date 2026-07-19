#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "../../dns_wire.h"

// Fuzzing harness for tsig_sign_packet to detect bounds check issues
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 10) return 0;
    
    size_t key_len = data[0];
    size_t alg_len = data[1];
    size_t initial_packet_len = data[2] * 4;
    size_t max_packet_len = initial_packet_len + data[3] * 4;
    if (max_packet_len > 4096) max_packet_len = 4096;
    
    if (key_len + alg_len + 10 > size) return 0;

    char key_name[256] = {0};
    char alg_name[256] = {0};
    
    size_t copy_k = key_len > 255 ? 255 : key_len;
    memcpy(key_name, data + 4, copy_k);
    key_name[copy_k] = '\0';
    
    size_t copy_a = alg_len > 255 ? 255 : alg_len;
    memcpy(alg_name, data + 4 + copy_k, copy_a);
    alg_name[copy_a] = '\0';
    
    tsig_key_t key;
    memset(&key, 0, sizeof(key));
    key.name = key_name;
    key.algorithm = alg_name;
    key.secret_decoded_len = 32;
    memcpy(key.secret_decoded, "12345678901234567890123456789012", 32);

    uint8_t *packet = malloc(max_packet_len);
    if (!packet) return 0;
    
    if (initial_packet_len > 0) {
        if (initial_packet_len > max_packet_len) initial_packet_len = max_packet_len;
        memset(packet, 0xAA, initial_packet_len);
    }
    
    size_t packet_len = initial_packet_len;
    uint8_t prior_mac[64];
    size_t prior_mac_len = 0;
    
    if (data[4] & 1) {
        prior_mac_len = 32;
        memset(prior_mac, 0xBB, 32);
    }

    uint16_t tsig_error = (data[5] % 2) == 0 ? 0 : 18;

    tsig_sign_packet(packet, &packet_len, max_packet_len, &key, tsig_error, prior_mac, &prior_mac_len, false);

    free(packet);
    return 0;
}

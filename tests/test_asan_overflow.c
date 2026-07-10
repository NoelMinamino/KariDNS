#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../dns_wire.h"
#include "../dns_config_parser.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>

int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode;
    (void)writable;
    return open(path, flags);
}

int main() {
    server_config_t cfg;
    
    // Test 1: 340 characters (accepted)
    memset(&cfg, 0, sizeof(cfg));
    char conf_340[1024];
    strcpy(conf_340, "key \"test\" { algorithm hmac-sha256; secret \"");
    for(int i=0; i<340; i++) strcat(conf_340, "A");
    strcat(conf_340, "\"; };");
    char* copy_340 = strdup(conf_340);
    int res1 = parse_named_conf(copy_340, &cfg);
    free(copy_340);
    if (res1 == 0) {
        printf("Test 1 Passed: Accepted 340 char secret\n");
    } else {
        printf("Test 1 Failed: Rejected 340 char secret!\n");
        return 1;
    }

    // Test 2: 344 characters (rejected)
    memset(&cfg, 0, sizeof(cfg));
    char conf_344[1024];
    strcpy(conf_344, "key \"test\" { algorithm hmac-sha256; secret \"");
    for(int i=0; i<344; i++) strcat(conf_344, "A");
    strcat(conf_344, "\"; };");
    char* copy_344 = strdup(conf_344);
    int res2 = parse_named_conf(copy_344, &cfg);
    free(copy_344);
    if (res2 == -1) {
        printf("Test 2 Passed: Rejected 344 char secret\n");
    } else {
        printf("Test 2 Failed: Accepted 344 char secret!\n");
        return 1;
    }
    
    printf("All tests passed safely.\n");
    return 0;
}

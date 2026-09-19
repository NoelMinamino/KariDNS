#ifndef DNS_PRIV_SANDBOX_H
#define DNS_PRIV_SANDBOX_H

#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>

extern bool g_bypass_cap_enter;

void enter_capsicum_sandbox(void);
void limit_server_socket_rights(int fd, bool is_listening_tcp);
void limit_client_socket_rights(int fd);
int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable);
int stat_via_dir_cache(const char *path, struct stat *sb);
int renameat_via_dir_cache(const char *old_path, const char *new_path);

#endif /* DNS_PRIV_SANDBOX_H */

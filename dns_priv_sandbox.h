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

/* options { user / group } の解決結果。privileged=true は root 起動で
 * setgroups/setgid/setuid による降格が必要なことを示す。 */
typedef struct {
  bool privileged;
  bool has_user;
  bool has_group;
  uid_t uid;
  gid_t gid;
} run_identity_t;

/* user/group を解決し、このプロセスが適用できるかを検証する(副作用なし)。
 * root 起動: user/group のいずれかが必須 (降格先)。
 * 非 root 起動: 他ユーザーへは切り替えられないため、user/group が指定されて
 *   いる場合は現在の uid/gid と一致しなければならない (未指定なら実行ユーザーのまま)。
 * 失敗時は err に理由を書き込み false を返す。 */
bool resolve_run_identity(const char *user, const char *group, run_identity_t *id,
                          char *err, size_t errlen);
/* resolve_run_identity() の結果に従い、root 起動なら権限を降格する。
 * 非 root 起動で検証に通った場合は何もしない。 */
bool apply_run_identity(const char *user, const char *group, char *err, size_t errlen);

#endif /* DNS_PRIV_SANDBOX_H */

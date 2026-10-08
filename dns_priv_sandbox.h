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
int list_dir_via_dir_cache(const char *file_path, void (*cb)(const char *name, void *ud), void *ud);
int unlink_via_dir_cache(const char *path);

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
/* 解決済みの id で降格する (apply_run_identity() の後半)。 */
bool apply_run_identity_id(const run_identity_t *id, char *err, size_t errlen);

/* 起動時に main() が1回だけ解決した実行ユーザー (O-18)。fork した子プロセス
 * (frontend / backend / broker) と、ログ・制御ソケットの所有者の引き渡しはこれを使い、
 * 実行中に名前を引き直さない。 */
extern run_identity_t g_run_identity;

/* getpwnam_r() / getgrnam_r() による名前解決 (スレッド安全)。見つからなければ false。 */
bool lookup_user_ids(const char *user, uid_t *uid, gid_t *gid);
bool lookup_group_id(const char *group, gid_t *gid);

/* Backend の終了。スレッドを起動した後は exit() ではなくこれを使う (O-15: atexit
 * ハンドラを他スレッドと並行して走らせない)。 */
__attribute__((noreturn)) void backend_exit(int code);

#endif /* DNS_PRIV_SANDBOX_H */

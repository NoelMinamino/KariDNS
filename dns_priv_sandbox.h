#ifndef DNS_PRIV_SANDBOX_H
#define DNS_PRIV_SANDBOX_H

#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>

/* Tests only: true makes enter_capsicum_sandbox() skip cap_enter().  A plain global, not a setter or a test macro: the unit tests are built
 * without a common test define, and the server never writes it. */
extern bool g_bypass_cap_enter;

void enter_capsicum_sandbox(void);
/* false (logged, errno set) = cap_rights_limit() failed and the descriptor keeps its wider rights; ENOSYS (no CAPABILITY_MODE in the kernel) is true */
bool limit_server_socket_rights(int fd, bool is_listening_tcp);
bool limit_client_socket_rights(int fd);
int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable);
int stat_via_dir_cache(const char *path, struct stat *sb);
int renameat_via_dir_cache(const char *old_path, const char *new_path);
int list_dir_via_dir_cache(const char *file_path, void (*cb)(const char *name, void *ud), void *ud);
int unlink_via_dir_cache(const char *path);
bool fd_drop_fchown(int fd);
bool dir_fd_cache_drop_fchown(void);
/* Opens dirpath (before the sandbox) for reading and marks it as a root of a directory tree: afterwards a directory below it that nobody
 * has opened yet can still be opened in capability mode, with openat() on this fd (O_RESOLVE_BENEATH, no ".."), instead of failing with
 * ENOTCAPABLE.  The server registers options { directory } and the directory of each zone file this way.  false (errno set) = not openable. */
bool dir_fd_cache_add_root(const char *dirpath);

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
bool apply_run_identity_id(const run_identity_t *id, char *err, size_t errlen);

/* 起動時に main() が1回だけ解決した実行ユーザー (O-18)。fork した子プロセス
 * (frontend / backend / broker) と、ログ・制御ソケットの所有者の引き渡しはこれを使い、
 * 実行中に名前を引き直さない。 */
extern run_identity_t g_run_identity;

/* getpwnam_r() / getgrnam_r() による名前解決 (スレッド安全)。見つからなければ false。
 * false のとき errno は 0 (名前が無い) か、引き当て自体の失敗 (ENOMEM、ERANGE ...)。数字の uid / gid は受け付けない (名前だけ)。 */
bool lookup_user_ids(const char *user, uid_t *uid, gid_t *gid);
bool lookup_group_id(const char *group, gid_t *gid);

/* Backend の終了。スレッドを起動した後は exit() ではなくこれを使う (O-15: atexit
 * ハンドラを他スレッドと並行して走らせない)。 */
__attribute__((noreturn)) void backend_exit(int code);

/* カバレッジ計測ビルドでプロファイルを書き出す (通常ビルドと capability mode の中では何もしない)。
 * LLVM のプロファイル用ランタイムは weak シンボルで参照するので、ランタイムが無い通常のビルドでは何もしない関数になる。
 * シグナルハンドラからも呼べる。 */
void backend_profile_flush(void);

#endif /* DNS_PRIV_SANDBOX_H */

#define OPENSSL_SUPPRESS_DEPRECATED 1
#include "dns_priv_sandbox.h"
#include "dns_server_internal.h"
#include "dns_dnstap.h"
#include "dns_utils.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <nl_types.h>
#include <pthread.h>
#include <pwd.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capsicum.h>
#include <sys/procctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// ============================================================================
// Capsicum capability-mode support
// ============================================================================
typedef struct dir_fd_entry {
  char *dirpath;
  int fd;
  bool is_writable;
  struct dir_fd_entry *next;
} dir_fd_entry_t;

static dir_fd_entry_t *g_dir_fd_table = NULL;
static pthread_mutex_t g_dir_fd_lock = PTHREAD_MUTEX_INITIALIZER;
bool g_bypass_cap_enter = false;
// g_capsicum_enabled is defined in dns_utils.c and declared in dns_utils.h

static bool path_has_dotdot_component(const char *p) {
  for (const char *s = p; (s = strstr(s, "..")) != NULL; s += 2) {
    if ((s == p || s[-1] == '/') && (s[2] == '\0' || s[2] == '/')) return true;
  }
  return false;
}

static int get_or_open_dir_fd(const char *dirpath, bool writable) {
  pthread_mutex_lock(&g_dir_fd_lock);
  for (dir_fd_entry_t *e = g_dir_fd_table; e; e = e->next) {
    if (strcmp(e->dirpath, dirpath) == 0) {
      if (!writable || e->is_writable) {
        int fd = e->fd;
        pthread_mutex_unlock(&g_dir_fd_lock);
        return fd;
      }
    }
  }
  if (atomic_load_explicit(&g_capsicum_enabled, memory_order_acquire)) {
    pthread_mutex_unlock(&g_dir_fd_lock);
    errno = ENOTCAPABLE;
    return -1;
  }
  int fd;
  char abs_dir[PATH_MAX];
  if (dirpath[0] == '/')
    fd = open(dirpath, O_DIRECTORY | O_CLOEXEC | O_RDONLY);
  else if (path_has_dotdot_component(dirpath) && g_startup_cwd[0] != '\0' &&
           snprintf(abs_dir, sizeof(abs_dir), "%s/%s", g_startup_cwd, dirpath) < (int)sizeof(abs_dir))
    /* D-24: 権利を絞った g_cwd_fd からは ".." を辿れない (FreeBSD の strict relative lookup)。
     * サンドボックスに入る前なら起動時ディレクトリからの絶対パスで開く。絶対パスは元から
     * 開けるので、これで新たに開ける範囲が広がるわけではない。キャッシュの鍵は dirpath のまま */
    fd = open(abs_dir, O_DIRECTORY | O_CLOEXEC | O_RDONLY);
  else
    fd = (g_cwd_fd >= 0)
             ? openat(g_cwd_fd, dirpath, O_DIRECTORY | O_CLOEXEC | O_RDONLY)
             : open(dirpath, O_DIRECTORY | O_CLOEXEC | O_RDONLY);
  if (fd < 0) {
    pthread_mutex_unlock(&g_dir_fd_lock);
    return -1;
  }
  cap_rights_t rights;
  if (writable)
    cap_rights_init(&rights, CAP_LOOKUP, CAP_READ, CAP_WRITE, CAP_CREATE,
                    CAP_FSTAT, CAP_FSTATFS, CAP_FTRUNCATE, CAP_SEEK,
                    CAP_RENAMEAT_SOURCE, CAP_RENAMEAT_TARGET, CAP_UNLINKAT,
                    CAP_FCNTL);
  else
    cap_rights_init(&rights, CAP_LOOKUP, CAP_READ, CAP_FSTAT, CAP_FSTATFS,
                    CAP_SEEK, CAP_FCNTL);
  if (cap_rights_limit(fd, &rights) != 0 && errno != ENOSYS) {
    close(fd);
    pthread_mutex_unlock(&g_dir_fd_lock);
    return -1;
  }
  dir_fd_entry_t *e = calloc(1, sizeof(*e));
  if (!e) {
    close(fd);
    pthread_mutex_unlock(&g_dir_fd_lock);
    return -1;
  }
  e->dirpath = strdup(dirpath);
  if (!e->dirpath) {
    free(e);
    close(fd);
    pthread_mutex_unlock(&g_dir_fd_lock);
    return -1;
  }
  e->fd = fd;
  e->is_writable = writable;
  e->next = g_dir_fd_table;
  g_dir_fd_table = e;
  pthread_mutex_unlock(&g_dir_fd_lock);
  return fd;
}

#ifndef O_RESOLVE_BENEATH
#define O_RESOLVE_BENEATH 0
#endif

int open_via_dir_cache(const char *path, int flags, mode_t mode,
                       bool writable) {
  char dirbuf[PATH_MAX], basebuf[PATH_MAX];
  if (!split_path_for_openat(path, dirbuf, sizeof(dirbuf), basebuf,
                             sizeof(basebuf))) {
    errno = EINVAL;
    return -1;
  }
  int dfd = get_or_open_dir_fd(dirbuf, writable);
  if (dfd < 0)
    return -1;
  return openat(dfd, basebuf, flags | O_RESOLVE_BENEATH, mode);
}

int stat_via_dir_cache(const char *path, struct stat *sb) {
  char dirbuf[PATH_MAX], basebuf[PATH_MAX];
  if (!split_path_for_openat(path, dirbuf, sizeof(dirbuf), basebuf,
                             sizeof(basebuf))) {
    errno = EINVAL;
    return -1;
  }
  int dfd = get_or_open_dir_fd(dirbuf, false);
  if (dfd < 0)
    return -1;
  return fstatat(dfd, basebuf, sb, 0);
}

int renameat_via_dir_cache(const char *old_path, const char *new_path) {
  char odir[PATH_MAX], obase[PATH_MAX], ndir[PATH_MAX], nbase[PATH_MAX];
  if (!split_path_for_openat(old_path, odir, sizeof(odir), obase,
                             sizeof(obase)))
    return -1;
  if (!split_path_for_openat(new_path, ndir, sizeof(ndir), nbase,
                             sizeof(nbase)))
    return -1;
  int ofd = get_or_open_dir_fd(odir, true);
  int nfd = get_or_open_dir_fd(ndir, true);
  if (ofd < 0 || nfd < 0)
    return -1;
  return renameat(ofd, obase, nfd, nbase);
}

/* file_path と同じディレクトリの各エントリー名で cb を呼ぶ。キャッシュ済みの書き込み用
 * ディレクトリ fd から "." を開き直して読む (サンドボックス内でも新たな資源は取らない。
 * dup だとファイル位置を共有し、同じディレクトリを読む別スレッドと干渉する) */
int list_dir_via_dir_cache(const char *file_path, void (*cb)(const char *name, void *ud), void *ud) {
  char dirbuf[PATH_MAX], basebuf[PATH_MAX];
  if (!split_path_for_openat(file_path, dirbuf, sizeof(dirbuf), basebuf, sizeof(basebuf))) {
    errno = EINVAL;
    return -1;
  }
  int dfd = get_or_open_dir_fd(dirbuf, true);
  if (dfd < 0)
    return -1;
  int fd = openat(dfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0)
    return -1;
  DIR *d = fdopendir(fd);
  if (!d) {
    close(fd);
    return -1;
  }
  struct dirent *de;
  while ((de = readdir(d)) != NULL)
    cb(de->d_name, ud);
  closedir(d);
  return 0;
}

int unlink_via_dir_cache(const char *path) {
  char dirbuf[PATH_MAX], basebuf[PATH_MAX];
  if (!split_path_for_openat(path, dirbuf, sizeof(dirbuf), basebuf, sizeof(basebuf))) {
    errno = EINVAL;
    return -1;
  }
  int dfd = get_or_open_dir_fd(dirbuf, true);
  if (dfd < 0)
    return -1;
  return unlinkat(dfd, basebuf, 0);
}

void limit_server_socket_rights(int fd, bool is_listening_tcp) {
  cap_rights_t rights;
  if (is_listening_tcp)
    cap_rights_init(&rights, CAP_ACCEPT, CAP_RECV, CAP_SEND, CAP_FCNTL,
                    CAP_EVENT, CAP_GETSOCKOPT, CAP_SETSOCKOPT, CAP_SHUTDOWN,
                    CAP_GETSOCKNAME, CAP_GETPEERNAME);
  else
    cap_rights_init(&rights, CAP_RECV, CAP_SEND, CAP_CONNECT, CAP_EVENT,
                    CAP_GETSOCKOPT, CAP_SETSOCKOPT, CAP_SHUTDOWN,
                    CAP_GETSOCKNAME, CAP_GETPEERNAME);
  cap_rights_limit(fd, &rights);
}

void limit_client_socket_rights(int fd) {
  cap_rights_t rights;
  cap_rights_init(&rights, CAP_RECV, CAP_SEND, CAP_FCNTL, CAP_EVENT,
                  CAP_GETSOCKOPT, CAP_SETSOCKOPT, CAP_SHUTDOWN, CAP_GETSOCKNAME,
                  CAP_GETPEERNAME);
  cap_rights_limit(fd, &rights);
}

void enter_capsicum_sandbox(void) {
#ifndef SANITIZER_BUILD
  if (g_dnstap_sock >= 0) {
    cap_rights_t rights;
    /* CAP_READ / CAP_RECV: 終了時に Frame Streams の FINISH を受け取る (O-03) */
    cap_rights_init(&rights, CAP_READ, CAP_RECV, CAP_WRITE, CAP_SEND, CAP_EVENT, CAP_GETSOCKOPT, CAP_SETSOCKOPT, CAP_FCNTL, CAP_SHUTDOWN);
    cap_rights_limit(g_dnstap_sock, &rights);
  }
  /* strerror() and syslog's %m look up libc's message catalog on first use
   * (/usr/share/nls/<locale>/libc.cat). In capability mode that lookup is a
   * Capsicum violation, which PROC_TRAPCAP turns into SIGTRAP: e.g. the dnstap
   * sender logging "write failed: %s" after the collector went away killed
   * the backend and, with it, the whole server. Open (and cache) the catalog
   * now, as caph_cache_catpages() does. */
  (void)catopen("libc", NL_CAT_LOCALE);
  if (!g_bypass_cap_enter) {
    int trapmode = PROC_TRAPCAP_CTL_ENABLE;
    procctl(P_PID, 0, PROC_TRAPCAP_CTL, &trapmode);
    if (cap_enter() != 0) {
      if (errno == ENOSYS) {
        /* O-02: カーネルに CAPABILITY_MODE が無い。サンドボックスなしで動き続けることを
         * 運用者が見落とさないよう LOG_CRIT で記録する (起動は続ける)。 */
        syslog(LOG_CRIT, "[Backend] Capsicum is not available in this kernel (cap_enter: ENOSYS); "
                         "running WITHOUT the capability-mode sandbox");
        fprintf(stderr, "[CRITICAL] [Backend] Capsicum is not available in this kernel (cap_enter: ENOSYS); "
                        "running WITHOUT the capability-mode sandbox\n");
        return;
      }
      int cap_errno = errno;
      syslog(LOG_ERR, "[Backend] cap_enter failed: %s; aborting startup", strerror(cap_errno));
      fprintf(stderr, "[ERROR] [Backend] cap_enter failed: %s; aborting startup\n", strerror(cap_errno));
      backend_exit(EXIT_FAILURE);
    }
  }
#endif
  atomic_store_explicit(&g_capsicum_enabled, true, memory_order_release);
}

// ============================================================================
// 実行ユーザー (options { user / group }) の解決と権限降格
// ============================================================================

/* O-18: getpwnam()/getgrnam() は結果を libc の静的バッファへ書くため、複数スレッドから
 * 同時に呼ぶと互いの結果を書き換える。名前の解決は *_r 版だけで行う。 */
#define ID_LOOKUP_BUF_MAX (1024 * 1024)

bool lookup_user_ids(const char *user, uid_t *uid, gid_t *gid) {
  char stackbuf[16384];
  char *buf = stackbuf;
  size_t len = sizeof(stackbuf);
  struct passwd pw, *res = NULL;
  int rc;
  while ((rc = getpwnam_r(user, &pw, buf, len, &res)) == ERANGE && len < ID_LOOKUP_BUF_MAX) {
    if (buf != stackbuf) free(buf);
    len *= 2;
    buf = malloc(len);
    if (!buf) return false;
  }
  bool ok = (rc == 0 && res != NULL);
  if (ok) {
    *uid = pw.pw_uid;
    *gid = pw.pw_gid;
  }
  if (buf != stackbuf) free(buf);
  return ok;
}

bool lookup_group_id(const char *group, gid_t *gid) {
  char stackbuf[16384];
  char *buf = stackbuf;
  size_t len = sizeof(stackbuf);
  struct group gr, *res = NULL;
  int rc;
  while ((rc = getgrnam_r(group, &gr, buf, len, &res)) == ERANGE && len < ID_LOOKUP_BUF_MAX) {
    if (buf != stackbuf) free(buf);
    len *= 2;
    buf = malloc(len);
    if (!buf) return false;
  }
  bool ok = (rc == 0 && res != NULL);
  if (ok) *gid = gr.gr_gid;
  if (buf != stackbuf) free(buf);
  return ok;
}

run_identity_t g_run_identity;

bool resolve_run_identity(const char *user, const char *group, run_identity_t *id,
                          char *err, size_t errlen) {
  memset(id, 0, sizeof(*id));
  id->uid = (uid_t)-1;
  id->gid = (gid_t)-1;
  if (user) {
    if (!lookup_user_ids(user, &id->uid, &id->gid)) {
      snprintf(err, errlen, "user '%s' not found", user);
      return false;
    }
    id->has_user = true;
  }
  if (group) {
    if (!lookup_group_id(group, &id->gid)) {
      snprintf(err, errlen, "group '%s' not found", group);
      return false;
    }
    id->has_group = true;
  }

  if (geteuid() == 0) {
    if (!user && !group) {
      snprintf(err, errlen, "running as root with no 'user'/'group' configured; "
                            "refusing to continue without privilege drop");
      return false;
    }
    id->privileged = true;
    return true;
  }

  /* 非root起動: POSIXでは非rootプロセスが別ユーザー/別グループへ切り替える
   * ことはできない。設定が実行ユーザー自身を指している場合のみ、降格を
   * 省略してそのまま稼働する。 */
  if (user && (getuid() != id->uid || geteuid() != id->uid)) {
    snprintf(err, errlen,
             "started as non-root uid %u but options { user \"%s\"; } is uid %u; "
             "a non-root process cannot switch to another user. Start karidns as root "
             "(it drops to '%s'), start it as '%s' itself, or remove the 'user' directive",
             (unsigned)geteuid(), user, (unsigned)id->uid, user, user);
    return false;
  }
  if (group && (getgid() != id->gid || getegid() != id->gid)) {
    snprintf(err, errlen,
             "started as non-root gid %u but options { group \"%s\"; } is gid %u; "
             "a non-root process cannot switch its primary group. Start karidns as root, "
             "start it with '%s' as its primary group, or remove the 'group' directive",
             (unsigned)getegid(), group, (unsigned)id->gid, group);
    return false;
  }
  return true;
}

bool apply_run_identity_id(const run_identity_t *id, char *err, size_t errlen) {
  if (!id->privileged)
    return true; /* 非root: 既に目的のユーザー/グループで稼働している */

  if (setgroups(0, NULL) != 0) {
    snprintf(err, errlen, "setgroups failed: %s", strerror(errno));
    return false;
  }
  if (setgid(id->gid) != 0) {
    snprintf(err, errlen, "setgid failed: %s", strerror(errno));
    return false;
  }
  if (id->has_user && setuid(id->uid) != 0) {
    snprintf(err, errlen, "setuid failed: %s", strerror(errno));
    return false;
  }
  if ((id->has_user && (getuid() != id->uid || geteuid() != id->uid)) ||
      getgid() != id->gid || getegid() != id->gid) {
    snprintf(err, errlen, "privilege drop verification failed");
    return false;
  }
  return true;
}

bool apply_run_identity(const char *user, const char *group, char *err, size_t errlen) {
  run_identity_t id;
  if (!resolve_run_identity(user, group, &id, err, errlen))
    return false;
  return apply_run_identity_id(&id, err, errlen);
}

// ============================================================================
// Backend の終了 (O-15)
// ============================================================================
#ifdef __clang__
__attribute__((weak)) int __llvm_profile_write_file(void);
#endif

/* Backend でスレッドを1本でも起動した後は exit() を使わない。exit() は atexit ハンドラ
 * (OpenSSL のクリーンアップなど) を、まだ動いている他のスレッドと並行して実行するため、
 * 解放済みのロックやテーブルを他スレッドが使う窓ができる。_exit() はそれを実行しない。
 * カバレッジ計測ビルドではプロファイルだけ先に書き出す。 */
__attribute__((noreturn)) void backend_exit(int code) {
#ifdef __clang__
  if (__llvm_profile_write_file)
    __llvm_profile_write_file();
#endif
  _exit(code);
}

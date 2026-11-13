#define OPENSSL_SUPPRESS_DEPRECATED 1
#include "dns_priv_sandbox.h"
#include "dns_server_internal.h"
#include "dns_log.h"
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
  bool is_root;   /* dir_fd_cache_add_root(): directories below this one can be opened through fd in capability mode */
  struct dir_fd_entry *next;
} dir_fd_entry_t;

static dir_fd_entry_t *g_dir_fd_table = NULL;
/* The one pthread mutex outside the RCU rule of CLAUDE.md: it guards the directory fd table, is held across the open of a directory, and is
 * taken only at startup, at reload (zone files, logs) and in the control paths; the query path never touches it. */
static pthread_mutex_t g_dir_fd_lock = PTHREAD_MUTEX_INITIALIZER;
static bool g_dir_fd_fchown_dropped = false;
bool g_bypass_cap_enter = false;
// g_capsicum_enabled is defined in dns_utils.c and declared in dns_utils.h

static bool path_has_dotdot_component(const char *p) {
  for (const char *s = p; (s = strstr(s, "..")) != NULL; s += 2) {
    if ((s == p || s[-1] == '/') && (s[2] == '\0' || s[2] == '/')) return true;
  }
  return false;
}

#ifndef O_RESOLVE_BENEATH
#define O_RESOLVE_BENEATH 0
#endif
#ifndef AT_RESOLVE_BENEATH
#define AT_RESOLVE_BENEATH 0
#endif

/* Beside the rights, the fcntl() commands a descriptor allows are cut to the ones the server uses (cap_fcntls_limit(2); CAP_FCNTL alone
 * allows all of them).  A file opened through a directory fd inherits the list.  ENOSYS (no CAPABILITY_MODE in the kernel) is not a failure. */
static void limit_fd_fcntls(int fd, uint32_t fcntls, const char *what) {
  if (cap_fcntls_limit(fd, fcntls) == 0 || errno == ENOSYS) return;
  syslog(LOG_ERR, "[Sandbox] cap_fcntls_limit(%s, fd %d) failed: %s; the descriptor allows all fcntl commands", what, fd, strerror(errno));
}

/* The cache key of a directory path: trailing slashes cut ("/var/dns/" and "/var/dns" are one directory, and a root registered as
 * "/var/dns/" must match the "/var/dns/zones" that open_dir_below_root_locked() looks for), the root "/" kept.  false = too long. */
static bool dir_key(const char *in, char *out, size_t cap) {
  size_t n = strlen(in);
  while (n > 1 && in[n - 1] == '/') n--;
  if (n >= cap) return false;
  memcpy(out, in, n);
  out[n] = '\0';
  return true;
}

/* Capability mode, directory not cached: open it through the fd of a root registered with dir_fd_cache_add_root() that contains it
 * (the longest such root), as a read-only directory below it.  Only a plain relative remainder is accepted ("a/b", no "..", no leading
 * '/'), and O_RESOLVE_BENEATH keeps symbolic links from leading out.  The new fd is cached like any other.  g_dir_fd_lock is held. */
static int open_dir_below_root_locked(const char *dirpath) {
  dir_fd_entry_t *best = NULL;
  size_t best_len = 0;
  for (dir_fd_entry_t *e = g_dir_fd_table; e; e = e->next) {
    if (!e->is_root) continue;
    size_t n = strlen(e->dirpath);
    /* the root "/" ends in the separator itself; any other key has none (dir_key()) */
    size_t sep = (n == 1 && e->dirpath[0] == '/') ? 0 : n;
    if (n == 0 || n >= strlen(dirpath) || strncmp(dirpath, e->dirpath, n) != 0 || dirpath[sep] != '/') continue;
    if (n > best_len) { best = e; best_len = n; }
  }
  if (!best) return -1;
  const char *rem = dirpath + best_len + (best_len == 1 && best->dirpath[0] == '/' ? 0 : 1);
  while (*rem == '/') rem++;
  if (!*rem || path_has_dotdot_component(rem)) return -1;
  int fd = openat(best->fd, rem, O_DIRECTORY | O_CLOEXEC | O_RDONLY | O_RESOLVE_BENEATH);
  if (fd < 0) return -1;
  cap_rights_t rights;
  cap_rights_init(&rights, CAP_LOOKUP, CAP_READ, CAP_FSTAT, CAP_FSTATFS, CAP_SEEK, CAP_FCNTL);
  dir_fd_entry_t *ne = calloc(1, sizeof(*ne));
  if ((cap_rights_limit(fd, &rights) != 0 && errno != ENOSYS) || !ne || !(ne->dirpath = strdup(dirpath))) {
    if (ne) free(ne->dirpath);
    free(ne);
    close(fd);
    return -1;
  }
  limit_fd_fcntls(fd, CAP_FCNTL_GETFL, "directory");   /* fdopen() of a file opened through it asks F_GETFL */
  ne->fd = fd;
  ne->next = g_dir_fd_table;
  g_dir_fd_table = ne;
  return fd;
}

/* A directory by its path (outside capability mode): absolute as it is, relative through g_cwd_fd, or from the start-up directory when it has
 * a ".." (D-24 below).  Plain O_RDONLY descriptor, no rights limited, not cached. */
static int open_dir_by_path(const char *dirpath) {
  char abs_dir[PATH_MAX];
  if (dirpath[0] == '/')
    return open(dirpath, O_DIRECTORY | O_CLOEXEC | O_RDONLY);
  if (path_has_dotdot_component(dirpath) && g_startup_cwd[0] != '\0' &&
      snprintf(abs_dir, sizeof(abs_dir), "%s/%s", g_startup_cwd, dirpath) < (int)sizeof(abs_dir))
    /* D-24: 権利を絞った g_cwd_fd からは ".." を辿れない (FreeBSD の strict relative lookup)。
     * サンドボックスに入る前なら起動時ディレクトリからの絶対パスで開く。絶対パスは元から
     * 開けるので、これで新たに開ける範囲が広がるわけではない。キャッシュの鍵は dirpath のまま */
    return open(abs_dir, O_DIRECTORY | O_CLOEXEC | O_RDONLY);
  return (g_cwd_fd >= 0) ? openat(g_cwd_fd, dirpath, O_DIRECTORY | O_CLOEXEC | O_RDONLY)
                         : open(dirpath, O_DIRECTORY | O_CLOEXEC | O_RDONLY);
}

static int get_or_open_dir_fd(const char *dirpath_in, bool writable) {
  char dirpath[PATH_MAX];
  if (!dir_key(dirpath_in, dirpath, sizeof(dirpath))) {
    errno = ENAMETOOLONG;
    return -1;
  }
  pthread_mutex_lock(&g_dir_fd_lock);
  int writable_hit = -1;
  for (dir_fd_entry_t *e = g_dir_fd_table; e; e = e->next) {
    if (strcmp(e->dirpath, dirpath) == 0) {
      if (writable ? e->is_writable : !e->is_writable) {
        int fd = e->fd;
        pthread_mutex_unlock(&g_dir_fd_lock);
        return fd;
      }
      if (!writable) writable_hit = e->fd;   /* a read-only request gets a read-only entry when there is one, else this */
    }
  }
  if (writable_hit >= 0) {
    pthread_mutex_unlock(&g_dir_fd_lock);
    return writable_hit;
  }
  if (atomic_load_explicit(&g_capsicum_enabled, memory_order_acquire)) {
    int bfd = writable ? -1 : open_dir_below_root_locked(dirpath);
    pthread_mutex_unlock(&g_dir_fd_lock);
    if (bfd < 0) errno = ENOTCAPABLE;
    return bfd;
  }
  int fd = open_dir_by_path(dirpath);
  if (fd < 0) {
    pthread_mutex_unlock(&g_dir_fd_lock);
    return -1;
  }
  cap_rights_t rights;
  if (writable) {
    cap_rights_init(&rights, CAP_LOOKUP, CAP_READ, CAP_WRITE, CAP_CREATE,
                    CAP_FSTAT, CAP_FSTATFS, CAP_FTRUNCATE, CAP_SEEK,
                    CAP_RENAMEAT_SOURCE, CAP_RENAMEAT_TARGET, CAP_UNLINKAT,
                    CAP_FCNTL);
    /* A log file opened at startup inherits this fd's rights and is handed to the run user with fchown()
     * (hand_off_logging_channels()); dir_fd_cache_drop_fchown() takes the right away again after that. */
    if (!g_dir_fd_fchown_dropped) cap_rights_set(&rights, CAP_FCHOWN);
  } else
    cap_rights_init(&rights, CAP_LOOKUP, CAP_READ, CAP_FSTAT, CAP_FSTATFS,
                    CAP_SEEK, CAP_FCNTL);
  if (cap_rights_limit(fd, &rights) != 0 && errno != ENOSYS) {
    close(fd);
    pthread_mutex_unlock(&g_dir_fd_lock);
    return -1;
  }
  limit_fd_fcntls(fd, CAP_FCNTL_GETFL, "directory");   /* fdopen() of a file opened through it asks F_GETFL */
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
  return openat(dfd, basebuf, flags | O_CLOEXEC | O_RESOLVE_BENEATH, mode);   /* never into a program-zone plugin or the loader */
}

int open_via_dir_cache_existing(const char *path, int flags) {
  char dirbuf[PATH_MAX], basebuf[PATH_MAX], key[PATH_MAX];
  if (!split_path_for_openat(path, dirbuf, sizeof(dirbuf), basebuf, sizeof(basebuf)) || !dir_key(dirbuf, key, sizeof(key))) {
    errno = EINVAL;
    return -1;
  }
  int dfd = -1;
  pthread_mutex_lock(&g_dir_fd_lock);
  for (dir_fd_entry_t *e = g_dir_fd_table; e && dfd < 0; e = e->next)
    if (e->is_writable && strcmp(e->dirpath, key) == 0) dfd = e->fd;
  pthread_mutex_unlock(&g_dir_fd_lock);
  if (dfd < 0) {
    errno = EACCES;
    return -1;
  }
  return openat(dfd, basebuf, (flags & ~O_CREAT) | O_CLOEXEC | O_RESOLVE_BENEATH);
}

int open_without_dir_cache(const char *path, int flags, mode_t mode) {
  char dirbuf[PATH_MAX], basebuf[PATH_MAX];
  if (atomic_load_explicit(&g_capsicum_enabled, memory_order_acquire)) {
    errno = ENOTCAPABLE;
    return -1;
  }
  if (!split_path_for_openat(path, dirbuf, sizeof(dirbuf), basebuf, sizeof(basebuf))) {
    errno = EINVAL;
    return -1;
  }
  int dfd = open_dir_by_path(dirbuf);
  if (dfd < 0) return -1;
  int fd = openat(dfd, basebuf, flags | O_CLOEXEC | O_NOFOLLOW | O_RESOLVE_BENEATH, mode);
  int e = errno;
  close(dfd);
  errno = e;
  return fd;
}

bool dir_fd_cache_add_root(const char *dirpath) {
  if (!dirpath || !*dirpath) {
    errno = EINVAL;
    return false;
  }
  char key[PATH_MAX];
  if (!dir_key(dirpath, key, sizeof(key))) {
    errno = ENAMETOOLONG;
    return false;
  }
  int fd = get_or_open_dir_fd(key, false);
  if (fd < 0) return false;
  pthread_mutex_lock(&g_dir_fd_lock);
  for (dir_fd_entry_t *e = g_dir_fd_table; e; e = e->next)
    if (strcmp(e->dirpath, key) == 0) e->is_root = true;
  pthread_mutex_unlock(&g_dir_fd_lock);
  return true;
}

/* cap_rights_limit() with the failure logged.  ENOSYS (a kernel without CAPABILITY_MODE) is not a failure: there are no rights to keep.
 * On false errno is the cause. */
static bool limit_fd_rights(int fd, const cap_rights_t *rights, const char *what) {
  if (cap_rights_limit(fd, rights) == 0 || errno == ENOSYS) return true;
  int e = errno;
  syslog(LOG_ERR, "[Sandbox] cap_rights_limit(%s, fd %d) failed: %s; the descriptor keeps its wider rights", what, fd, strerror(e));
  errno = e;
  return false;
}

/* Takes CAP_FCHOWN off fd (a file opened through a writable directory fd inherits it). */
bool fd_drop_fchown(int fd) {
  cap_rights_t rights;
  if (fd < 0 || cap_rights_get(fd, &rights) != 0 || !cap_rights_is_set(&rights, CAP_FCHOWN)) return true;
  cap_rights_clear(&rights, CAP_FCHOWN);
  return limit_fd_rights(fd, &rights, "drop CAP_FCHOWN");
}

/* After the startup hand-off of the logs: the writable directory fds lose CAP_FCHOWN, and ones opened later do not get
 * it.  The processes forked after this (Backend, routers, broker) run as the run user anyway. */
bool dir_fd_cache_drop_fchown(void) {
  bool ok = true;
  pthread_mutex_lock(&g_dir_fd_lock);
  g_dir_fd_fchown_dropped = true;
  for (dir_fd_entry_t *e = g_dir_fd_table; e; e = e->next)
    if (e->is_writable && !fd_drop_fchown(e->fd)) ok = false;
  pthread_mutex_unlock(&g_dir_fd_lock);
  return ok;
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
  return fstatat(dfd, basebuf, sb, AT_RESOLVE_BENEATH);   /* as the open does: a symbolic link does not lead out of the directory */
}

int renameat_via_dir_cache(const char *old_path, const char *new_path) {
  char odir[PATH_MAX], obase[PATH_MAX], ndir[PATH_MAX], nbase[PATH_MAX];
  if (!split_path_for_openat(old_path, odir, sizeof(odir), obase,
                             sizeof(obase)) ||
      !split_path_for_openat(new_path, ndir, sizeof(ndir), nbase,
                             sizeof(nbase))) {
    errno = EINVAL;
    return -1;
  }
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
  errno = 0;
  while ((de = readdir(d)) != NULL) {
    if (strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0) cb(de->d_name, ud);
    errno = 0;
  }
  int rd_errno = errno;   /* readdir() returns NULL for the end and for an error; only errno tells them apart */
  closedir(d);
  if (rd_errno != 0) {
    errno = rd_errno;
    return -1;
  }
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

bool limit_server_socket_rights(int fd, bool is_listening_tcp) {
  cap_rights_t rights;
  if (is_listening_tcp)
    cap_rights_init(&rights, CAP_ACCEPT, CAP_RECV, CAP_SEND, CAP_FCNTL,
                    CAP_EVENT, CAP_GETSOCKOPT, CAP_SETSOCKOPT, CAP_SHUTDOWN,
                    CAP_GETSOCKNAME, CAP_GETPEERNAME);
  else
    cap_rights_init(&rights, CAP_RECV, CAP_SEND, CAP_CONNECT, CAP_EVENT,
                    CAP_GETSOCKOPT, CAP_SETSOCKOPT, CAP_SHUTDOWN,
                    CAP_GETSOCKNAME, CAP_GETPEERNAME);
  bool ok = limit_fd_rights(fd, &rights, is_listening_tcp ? "listening socket" : "server socket");
  if (ok) limit_fd_fcntls(fd, CAP_FCNTL_GETFL | CAP_FCNTL_SETFL, "server socket");   /* O_NONBLOCK is all the server sets */
  return ok;
}

bool limit_client_socket_rights(int fd) {
  cap_rights_t rights;
  cap_rights_init(&rights, CAP_RECV, CAP_SEND, CAP_FCNTL, CAP_EVENT,
                  CAP_GETSOCKOPT, CAP_SETSOCKOPT, CAP_SHUTDOWN, CAP_GETSOCKNAME,
                  CAP_GETPEERNAME);
  bool ok = limit_fd_rights(fd, &rights, "client socket");
  if (ok) limit_fd_fcntls(fd, CAP_FCNTL_GETFL | CAP_FCNTL_SETFL, "client socket");
  return ok;
}

void enter_capsicum_sandbox(void) {
#ifndef SANITIZER_BUILD
  /* the sender thread may reconnect meanwhile (it limits its own socket): read the descriptor once */
  int dtap = atomic_load_explicit(&g_dnstap_sock, memory_order_acquire);
  if (dtap >= 0) {
    cap_rights_t rights;
    /* CAP_READ / CAP_RECV: 終了時に Frame Streams の FINISH を受け取る (O-03) */
    cap_rights_init(&rights, CAP_READ, CAP_RECV, CAP_WRITE, CAP_SEND, CAP_EVENT, CAP_GETSOCKOPT, CAP_SETSOCKOPT, CAP_FCNTL, CAP_SHUTDOWN);
    if (!limit_fd_rights(dtap, &rights, "dnstap socket")) {
      fprintf(stderr, "[ERROR] [Backend] cannot limit the rights of the dnstap socket; aborting startup\n");
      backend_exit(EXIT_FAILURE);
    }
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
    if (!buf) { errno = ENOMEM; return false; }
  }
  bool ok = (rc == 0 && res != NULL);
  int lookup_errno = rc;   /* 0 = the name is not there; else the error of the lookup */
  if (ok) {
    *uid = pw.pw_uid;
    *gid = pw.pw_gid;
  }
  if (buf != stackbuf) free(buf);
  errno = lookup_errno;
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
    if (!buf) { errno = ENOMEM; return false; }
  }
  bool ok = (rc == 0 && res != NULL);
  if (ok) *gid = gr.gr_gid;
  if (buf != stackbuf) free(buf);
  errno = rc;   /* 0 = the name is not there; else the error of the lookup */
  return ok;
}

run_identity_t g_run_identity;

bool resolve_run_identity(const char *user, const char *group, run_identity_t *id,
                          char *err, size_t errlen) {
  memset(id, 0, sizeof(*id));
  id->uid = (uid_t)-1;
  id->gid = (gid_t)-1;
  /* P4: a name that resolves to uid 0 (or to the root group) is root by another name: the privilege drop would be no
   * drop.  Refused for user / group and loader-user / loader-group here (program-user: m_start_request(), dns_plugin_sup.c), at the
   * configuration check and at start (identity_names_root(), dns_utils.c; karicheck asks it too); not at reload, which cannot change them and runs in capability mode. */
  if (identity_names_root(user, group, err, errlen)) return false;
  if (user) {
    if (!lookup_user_ids(user, &id->uid, &id->gid)) {
      int e = errno;   /* 0: not in the user database; else the lookup itself failed */
      if (e) snprintf(err, errlen, "user '%s' could not be looked up: %s", user, strerror(e));
      else snprintf(err, errlen, "user '%s' not found", user);
      return false;
    }
    id->has_user = true;
  }
  if (group) {
    if (!lookup_group_id(group, &id->gid)) {
      int e = errno;
      if (e) snprintf(err, errlen, "group '%s' could not be looked up: %s", group, strerror(e));
      else snprintf(err, errlen, "group '%s' not found", group);
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
    /* group だけでは setgid しか行わず uid 0 のまま残る。呼び出し側 (起動前検証、ローダーの supervisor) にも同じ検査があるが、
     * 降格の可否はここで一度に決める */
    if (!user) {
      snprintf(err, errlen, "running as root with 'group' but no 'user': the process would keep uid 0; configure the user as well");
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
  /* 降格が戻せないこと: root に戻れず (setuid(0) が失敗する)、補助グループも残っていない
   * (FreeBSD 14 までは getgroups() が実効 GID を先頭に返す。15 以降は補助グループだけ: 0 個) */
  gid_t groups[2];
  int ngroups = getgroups(2, groups);
  bool groups_ok = ngroups == 0 || (ngroups == 1 && groups[0] == getegid());
  if ((id->uid != 0 && setuid(0) == 0) || !groups_ok) {
    snprintf(err, errlen, "privilege drop verification failed: root can be regained or supplementary groups remain");
    return false;
  }
  return true;
}

// ============================================================================
// Backend の終了 (O-15)
// ============================================================================
#ifdef __clang__
__attribute__((weak)) int __llvm_profile_write_file(void);
#endif

/* カバレッジ計測ビルド (clang の -fprofile-instr-generate) でだけプロファイルを書き出す。
 * プロファイル用ランタイムが無い通常のビルドでは weak シンボルが NULL なので何もしない。
 * capability mode の中では呼ばない: FreeBSD の LLVM プロファイルランタイムは書き出しの前後で
 * procctl() (lprofSuspendSigKill / lprofRestoreSigKill) を呼び、capability mode では ECAPMODE になる。
 * Backend は PROC_TRAPCAP を有効にしているので SIGTRAP (TRAP_CAP) で落ちる (終了ステータス 133)。
 * Backend のカウンタは continuous mode (-mllvm -runtime-counter-relocation=true) で起動時に
 * mmap 済みのプロファイルへ直接加算されるので、capability mode の中では書き出さなくても失われない。
 * 書き出しが必要な classic mode でも、cap_enter() 後はプロファイルを open() できないので元々書けない。 */
void backend_profile_flush(void) {
#ifdef __clang__
  unsigned int capmode = 0;
  if (__llvm_profile_write_file && !(cap_getmode(&capmode) == 0 && capmode != 0))
    __llvm_profile_write_file();
#endif
}

/* Backend でスレッドを1本でも起動した後は exit() を使わない。exit() は atexit ハンドラ
 * (OpenSSL のクリーンアップなど) を、まだ動いている他のスレッドと並行して実行するため、
 * 解放済みのロックやテーブルを他スレッドが使う窓ができる。_exit() はそれを実行しない。
 * カバレッジ計測ビルドではプロファイルだけ先に書き出す。 */
__attribute__((noreturn)) void backend_exit(int code) {
  fflush(stdout);   /* _exit() does not: a message printed with printf() before a failed start would be lost when stdout is a pipe or a file */
  backend_profile_flush();
  _exit(code);
}

#!/bin/sh
# ci_cache_env.sh - sourced by the FreeBSD VM steps of .github/workflows/ci.yml and freebsd.yml: the caches of the CI in the workspace.
#
# usage: . tests/ci_cache_env.sh                          the package cache only
#        CI_CCACHE=1; . tests/ci_cache_env.sh             also the compiler cache (the build jobs; "." passes no arguments in sh)
#
# .ci-cache/pkg   PKG_CACHEDIR: the .pkg files.  The job restores the directory (actions/cache/restore) before the VM starts, and the VM action copies
#                 the workspace into the VM.  pkg install takes a package from there only when its size and checksum match the repository catalogue,
#                 else it fetches it again: a stale or damaged file costs a download, never a wrong package.  Saved by the build jobs on main / schedule /
#                 dispatch runs only (never from a pull request), with every package any job of the release installs (tests/ci_pkg_fetch_all.sh).
# .ci-cache/ccache  CCACHE_DIR, and .ci-cache/bin first in PATH: c++ and clang++ are links to ccache, cc and clang to tests/ci_cc_split.sh (ccache
#                 one source at a time also for the commands that compile and link many sources); both run the next compiler of that name in PATH
#                 (so coverage-build's CC=clang goes through it too, with no Makefile change).  The objects carry the absolute path of the tree
#                 (llvm-cov mapping, the profile path of the instrumented loader): the path of the tree is hashed into every entry
#                 (CCACHE_EXTRAFILES = a file holding pwd -P), so a tree at another path never gets an object made for this one.
# .ci-cache is never packed (tests/coverage_pack.sh) nor looked at by tests/freebsd_no_rebuild_check.sh.
CI_CACHE=$(pwd -P)/.ci-cache
mkdir -p "$CI_CACHE/pkg"
PKG_CACHEDIR="$CI_CACHE/pkg"
export PKG_CACHEDIR
echo "package cache: $PKG_CACHEDIR ($(find "$PKG_CACHEDIR" -name '*.pkg' | wc -l | tr -d ' ') files, $(du -sh "$PKG_CACHEDIR" | cut -f1))"
if [ "${CI_CCACHE:-0}" = 1 ]; then
    pkg install -y ccache4
    mkdir -p "$CI_CACHE/bin" "$CI_CACHE/ccache"
    for c in c++ clang++; do ln -sf "$(command -v ccache)" "$CI_CACHE/bin/$c"; done
    cp tests/ci_cc_split.sh "$CI_CACHE/bin/ci_cc_split" && chmod 755 "$CI_CACHE/bin/ci_cc_split"
    for c in cc clang; do ln -sf ci_cc_split "$CI_CACHE/bin/$c"; done
    pwd -P > "$CI_CACHE/ccache.tree"
    CCACHE_DIR="$CI_CACHE/ccache"
    CCACHE_EXTRAFILES="$CI_CACHE/ccache.tree"
    CCACHE_MAXSIZE=${CCACHE_MAXSIZE:-3G}
    PATH="$CI_CACHE/bin:$PATH"
    export CCACHE_DIR CCACHE_EXTRAFILES CCACHE_MAXSIZE PATH
    ccache -z > /dev/null
    echo "compiler cache: $CCACHE_DIR ($(du -sh "$CCACHE_DIR" | cut -f1)), cc is $(command -v cc)"
fi

#!/bin/sh
# ci_pkg_fetch_all.sh - fill the package cache of the CI (tests/ci_cache_env.sh, PKG_CACHEDIR) with every package a FreeBSD job installs.
#
# usage: sh tests/ci_pkg_fetch_all.sh RELEASE     (in the VM of the build job, after . tests/ci_cache_env.sh; in the background of the build)
#
# The names come from the "pkg install -y" lines of .github/workflows/ci.yml and freebsd.yml themselves, so the list cannot fall behind them:
# for 14.4 the lines of freebsd.yml without the browser job (it runs on 15.1 only), for 15.1 all of them (the coverage jobs are 15.1).
# "llvm${V}-lite" is the one of the base clang, as the coverage jobs install it.  pkg fetch -d takes the dependencies as well.  One name at a
# time: a name the repository does not have (firefox on 15 latest, now and then: the jobs install firefox-esr) costs its own line, not the others.
set -u
rel="${1:-}"
[ -n "$rel" ] || { echo "usage: $0 RELEASE" >&2; exit 2; }
V=$(cc --version | sed -n 's/.*clang version \([0-9][0-9]*\).*/\1/p' | head -n 1)
case "$rel" in
    15.*) files=".github/workflows/ci.yml .github/workflows/freebsd.yml" ;;
    *) files=".github/workflows/freebsd.yml" ;;
esac
names=$(for f in $files; do
    if [ "$f" = .github/workflows/freebsd.yml ] && [ "${rel%%.*}" != 15 ]; then
        sed '/^  webadmin-gui:/,$d' "$f"
    else
        cat "$f"
    fi
done | sed -n 's/^[[:space:]]*pkg install -y //p' | sed 's/#.*//' | tr -d '"' | tr ' ' '\n' | sed "s/\${V}/$V/" | grep -E '^[A-Za-z0-9]'
    echo ccache4)                                                       # (CI_CCACHE=1 of tests/ci_cache_env.sh)
names=$(echo "$names" | sort -u)
echo "packages to cache for $rel: $(echo $names)"
fail=0
for n in $names; do
    pkg fetch -y -d "$n" > /dev/null 2>&1 || { echo "pkg fetch $n failed"; fail=$((fail + 1)); }
done
echo "package cache: $(find "${PKG_CACHEDIR:?}" -name '*.pkg' | wc -l | tr -d ' ') files, $(du -sh "$PKG_CACHEDIR" | cut -f1); $fail name(s) not fetched"

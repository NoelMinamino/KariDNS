#!/bin/sh
# ci_cc_split.sh - the C compiler of the CI build jobs (tests/ci_cache_env.sh links .ci-cache/bin/cc and clang to it): ccache, one source at a time.
#
# usage: cc ARGS...    (as cc or clang, first in PATH; CI only, never in a local build)
#
# Most unit-test, fuzzer and tool rules of the Makefile compile and link 10-40 sources in one command ($(CC) $(CFLAGS) $(X_SRCS) -o x $(LDFLAGS)),
# which ccache cannot cache.  For such a command (two or more .c sources, -o OUT, no -c/-S/-E/-M, nothing it does not know) this runs
#     ccache CC ARGS-for-the-compile -c SRC -o TMP/N.o      for each source, in order
#     CC ARGS with each SRC replaced by TMP/N.o              the link, uncached
# The compile gets every argument but the link-only ones (-l, -L, -Wl,, -Xlinker, -static, -shared, -rdynamic, objects and libraries); the link gets
# them all, so -flto, -fsanitize=, -fprofile-instr-generate, -pthread, -O and -march reach both, as in the one command (clang runs the same jobs:
# cc1 for each source with the same flags, then the linker).  -Qunused-arguments keeps the two steps quiet about the arguments the other one uses.
# Any other command goes to ccache unchanged.  When the command is one this does not know, or a split step fails, the original command runs
# unchanged with the real compiler: this never makes a build fail that would pass without it (a real error is reported by the original command).
# The binaries are the same as without it (checked in CI: the build of every job compared file by file).
# CI_CC_SPLIT=0 turns the split off (every command goes to ccache unchanged, as before).
set -u
self=$(basename "$0")
bindir=$(cd "$(dirname "$0")" && pwd -P)
real=
oifs=$IFS; IFS=:
for d in $PATH; do
    [ -n "$d" ] && [ "$(cd "$d" 2>/dev/null && pwd -P)" != "$bindir" ] && [ -x "$d/$self" ] && { real="$d/$self"; break; }
done
IFS=$oifs
[ -n "$real" ] || { echo "ci_cc_split.sh: no $self in PATH after $bindir" >&2; exit 127; }
ccache=$(command -v ccache) || exec "$real" "$@"

q() { # $1 single-quoted for eval
    case $1 in *\'*) printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")" ;; *) printf "'%s'" "$1" ;; esac
}

[ "${CI_CC_SPLIT:-1}" = 1 ] || exec "$ccache" "$real" "$@"

orig=
for a in "$@"; do orig="$orig $(q "$a")"; done

# sort the arguments: comp = the compile arguments (no sources, no -o), link = all of them with each source replaced by @N@
comp= link= srcs= n=0 out= next= bad=
for a in "$@"; do
    if [ -n "$next" ]; then
        case $next in
        out) out=$a; link="$link -o $(q "$a")" ;;
        link) link="$link $(q "$a")" ;;
        both) comp="$comp $(q "$a")"; link="$link $(q "$a")" ;;
        esac
        next=
        continue
    fi
    case $a in
    -o) next=out ;;
    -Xlinker) next=link; link="$link $(q "$a")" ;;
    -I|-D|-U|-include|-imacros|-isystem|-iquote|-idirafter|-mllvm|-Xclang|-target|-arch) next=both; comp="$comp $(q "$a")"; link="$link $(q "$a")" ;;
    -c|-S|-E|-M*|-x|-x*|-o?*|-Xassembler|-Xpreprocessor|-save-temps*|--serialize-diagnostics|-|@*|*.s|*.S|*.i|*.cc|*.cpp|*.cxx|*.m) bad=1; break ;;
    -l*|-L*|-Wl,*|-static|-shared|-rdynamic|-nostdlib|-nodefaultlibs) link="$link $(q "$a")" ;;
    -*) comp="$comp $(q "$a")"; link="$link $(q "$a")" ;;
    *.o|*.a|*.so|*.so.*) link="$link $(q "$a")" ;;
    *.c) n=$((n + 1)); srcs="$srcs $(q "$a")"; link="$link @$n@" ;;
    *) bad=1; break ;;
    esac
done
[ -n "$next" ] && bad=1
if [ -n "$bad" ] || [ "$n" -lt 2 ] || [ -z "$out" ]; then
    if [ "$n" -ge 2 ]; then exec "$real" "$@"; fi # a multi-source command it does not know: the real compiler, unchanged
    exec "$ccache" "$real" "$@"
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/ccsplit.XXXXXX") || exec "$real" "$@"
trap 'rm -rf "$tmp"' EXIT
i=0
eval "set -- $srcs"
for s in "$@"; do
    i=$((i + 1))
    eval "\"\$ccache\" \"\$real\" $comp -Qunused-arguments -c $(q "$s") -o \"\$tmp/$i.o\"" || { split_failed=1; break; }
    link=$(printf '%s' "$link" | sed "s|@$i@|'$tmp/$i.o'|")
done
if [ -z "${split_failed:-}" ] && eval "\"\$real\" $link -Qunused-arguments"; then
    exit 0
fi
echo "ci_cc_split.sh: the split build of $out failed: running the original command" >&2
rm -rf "$tmp"
trap - EXIT
eval "set -- $orig"
exec "$real" "$@"

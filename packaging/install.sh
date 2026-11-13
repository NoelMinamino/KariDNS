#!/bin/sh
# install.sh - the installer behind `make install` and `make uninstall` (the Makefile, "Installation"; docs/building.md).
#
#   sh packaging/install.sh install|uninstall DESTDIR ENTRY...
#
# The Makefile holds the one list of what is installed where; this script only carries it out.  ENTRY is KIND:SOURCE:TARGET, TARGET an
# absolute path (PREFIX, SYSCONFDIR, ... already put in by make); DESTDIR, when not empty, is put before every TARGET (a staging root).
#   0555, 0444, 0644 (a mode)  the file SOURCE, with that mode
#   man                        the manual page SOURCE, mode 0444; with MANCOMPRESS=yes (the default on FreeBSD: MANCOMPRESS=auto) it is
#                              installed compressed as TARGET.gz (gzip -9n: the same bytes on every run)
#   tree                       every file under the directory SOURCE, mode 0444, in directories of mode 0755; a directory .bin is left out (the
#                              links of npm), and anything that is neither a regular file nor a directory is refused
# Every target name may hold only letters, digits and _ . / + @ - (the package lists and the shell take them as they are).  Owner and group are
# root (0:0) when this runs as root, else the user that runs it: a package is built unprivileged and its list names root:wheel itself.  A
# configuration file is never installed: the samples are TARGET.sample, so an existing configuration is never overwritten.
# uninstall removes the files install puts there (for a manual page both TARGET and TARGET.gz), then the directories of KariDNS that are left
# empty: a directory is removed only when it is empty and its path below DESTDIR has a component that starts with "karidns"
# (etc/karidns/zones, share/doc/karidns, libexec/karidns-signer/...); bin, sbin, share/man/man8 and the like are never removed.
set -eu

die() { echo "install.sh: $*" >&2; exit 1; }

[ $# -ge 2 ] || die "usage: install.sh install|uninstall DESTDIR ENTRY..."
ACTION=$1
DEST=$2
shift 2
case $ACTION in install|uninstall) ;; *) die "unknown action '$ACTION' (install, uninstall)" ;; esac
case $DEST in ''|/*) ;; *) die "DESTDIR must be an absolute path: '$DEST'" ;; esac
DEST=${DEST%/}

OWN=
if [ "$(id -u)" = 0 ]; then OWN="-o 0 -g 0"; fi
GZ=no
case ${MANCOMPRESS:-auto} in
    yes) GZ=yes ;;
    no) ;;
    auto) [ "$(uname -s)" = FreeBSD ] && GZ=yes ;;
    *) die "MANCOMPRESS must be yes, no or auto: '${MANCOMPRESS}'" ;;
esac

checkname() {
    case $1 in
        /*) ;;
        *) die "not an absolute target: '$1'" ;;
    esac
    case $1 in
        *[!A-Za-z0-9_./+@-]*|*/../*|*/..) die "a target name holds a character that is not allowed: '$1'" ;;
    esac
}

# mkdirs DIR: DIR and its missing parents, mode 0755 (an existing directory is left as it is)
mkdirs() {
    [ -d "$1" ] && return 0
    mkdirs "$(dirname "$1")"
    install -d -m 0755 $OWN "$1"
}

# put MODE SOURCE TARGET
put() {
    checkname "$3"
    [ -f "$2" ] || die "$2 is missing (build it first: make, make karidns-dbloader karidns-zone; for signer/ and webadmin/: npm ci --omit=dev --ignore-scripts)"
    mkdirs "$DEST$(dirname "$3")"
    install -m "$1" $OWN "$2" "$DEST$3"
}

# rmdirs DIR: DIR and its parents while they are empty and a directory of KariDNS
rmdirs() {
    d=$1
    while :; do
        case ${d#"$DEST"} in
            */karidns*) ;;
            *) return 0 ;;
        esac
        rmdir "$d" 2>/dev/null || return 0
        d=$(dirname "$d")
    done
}

# tree_files SOURCE: the files of the tree, relative, sorted
tree_files() {
    [ -d "$1" ] || die "$1 is missing (npm ci --omit=dev --ignore-scripts in its program directory first)"
    bad=$(cd "$1" && find . -type d -name .bin -prune -o ! -type f ! -type d -print)
    [ -z "$bad" ] || die "$1 holds something that is neither a regular file nor a directory: $(echo "$bad" | head -3 | tr '\n' ' ')"
    (cd "$1" && find . -type d -name .bin -prune -o -type f -print) | sed 's|^\./||' | LC_ALL=C sort
}

for e in "$@"; do
    kind=${e%%:*}
    rest=${e#*:}
    src=${rest%%:*}
    tgt=${rest#*:}
    [ -n "$kind" ] && [ -n "$src" ] && [ -n "$tgt" ] && [ "$src:$tgt" = "$rest" ] || die "bad entry '$e' (KIND:SOURCE:TARGET)"
    checkname "$tgt"
    case $kind in
        man)
            if [ "$ACTION" = install ]; then
                if [ $GZ = yes ]; then
                    [ -f "$src" ] || die "$src is missing (make man)"
                    tmp=$(mktemp "${TMPDIR:-/tmp}/karidns_man.XXXXXX")
                    gzip -9 -n -c "$src" > "$tmp" || { rm -f "$tmp"; die "gzip $src failed"; }
                    put 0444 "$tmp" "$tgt.gz" || { rm -f "$tmp"; exit 1; }
                    rm -f "$tmp"
                else
                    put 0444 "$src" "$tgt"
                fi
            else
                rm -f "$DEST$tgt" "$DEST$tgt.gz"
                rmdirs "$DEST$(dirname "$tgt")"
            fi
            ;;
        tree)
            files=$(tree_files "$src")
            if printf '%s\n' "$files" | grep -q '[^A-Za-z0-9_./+@-]'; then
                die "a file name in $src holds a character that is not allowed: $(printf '%s\n' "$files" | grep '[^A-Za-z0-9_./+@-]' | head -1)"
            fi
            for f in $files; do
                if [ "$ACTION" = install ]; then
                    put 0444 "$src/$f" "$tgt/$f"
                else
                    rm -f "$DEST$tgt/$f"
                    rmdirs "$DEST$(dirname "$tgt/$f")"
                fi
            done
            ;;
        0[0-7][0-7][0-7])
            if [ "$ACTION" = install ]; then
                put "$kind" "$src" "$tgt"
            else
                rm -f "$DEST$tgt"
                rmdirs "$DEST$(dirname "$tgt")"
            fi
            ;;
        *) die "bad kind '$kind' in '$e' (a mode such as 0555, man, tree)" ;;
    esac
done
exit 0

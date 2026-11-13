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
#   owndir (SOURCE -)          TARGET is a directory of KariDNS's own (SYSCONFDIR/karidns, DATADIR, DOCDIR, LIBEXECDIR/karidns-signer, ...):
#                              uninstall removes it and the directories below it when they are left empty; install does nothing with it
# Every source is checked before anything is copied: when one is missing, nothing is installed and the message names what to build.  Every
# target name may hold only letters, digits and _ . / + @ - (the package lists and the shell take them as they are).  Owner and group are
# root (0:0) when this runs as root, else the user that runs it: a package is built unprivileged and its list names root:wheel itself.  A
# configuration file is never installed: the samples are TARGET.sample, so an existing configuration is never overwritten.
# uninstall removes the files install puts there (for a manual page both TARGET and TARGET.gz) and, for a tree, every file of the installed
# directory TARGET (what is there, not what SOURCE holds now: SOURCE may be gone or changed since; a TARGET that is a symbolic link or holds
# anything but files and directories is refused before anything is removed).  Then it removes the directories left empty, only at or below
# an owndir whose last component starts with "karidns": bin, sbin, share/man/man8, PREFIX itself and the like are never removed.
set -eu

TMPF=
trap '[ -z "$TMPF" ] || rm -f "$TMPF"' EXIT
trap 'exit 130' INT TERM HUP
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
    mkdirs "$DEST$(dirname "$3")"
    install -m "$1" $OWN "$2" "$DEST$3"
}

# the directories of KariDNS (the owndir entries, without DESTDIR: their names hold no space, DESTDIR may)
ROOTS=
# rmdirs DIR: DIR (DESTDIR put before it) and its parents while they are empty and at or below one of ROOTS
rmdirs() {
    d=$1
    while :; do
        mine=no
        for r in $ROOTS; do
            case ${d#"$DEST"} in "$r"|"$r"/*) mine=yes ;; esac
        done
        [ $mine = yes ] || return 0
        rmdir "$d" 2>/dev/null || return 0
        d=$(dirname "$d")
    done
}

# tree_files SOURCE: the files of the tree, relative, sorted
tree_files() {
    (cd "$1" && find . -type d -name .bin -prune -o -type f -print) | sed 's|^\./||' | LC_ALL=C sort
}

# hint SOURCE: what makes a missing SOURCE
hint() {
    case $1 in
        karidns-dbloader|karidns-zone) echo "make karidns-dbloader karidns-zone (or leave the database parts out: DB_DRIVERS=)" ;;
        karidns|karictl|karicheck|karidns-tapstat) echo "make all" ;;
        dag) echo "make dag (or make all)" ;;
        man/*) echo "make man" ;;
        signer/node_modules) echo "npm ci --omit=dev --ignore-scripts in signer/" ;;
        webadmin/node_modules) echo "npm ci --omit=dev --ignore-scripts in webadmin/" ;;
        *) echo "a file of the source tree: is this a complete copy?" ;;
    esac
}

# 1. every entry is checked before anything is installed or removed
MISSING=
HINTS=
for e in "$@"; do
    kind=${e%%:*}
    rest=${e#*:}
    src=${rest%%:*}
    tgt=${rest#*:}
    [ -n "$kind" ] && [ -n "$src" ] && [ -n "$tgt" ] && [ "$src:$tgt" = "$rest" ] || die "bad entry '$e' (KIND:SOURCE:TARGET)"
    checkname "$tgt"
    case $kind in
        owndir)
            [ "$src" = - ] || die "bad entry '$e' (owndir:-:TARGET)"
            case ${tgt##*/} in karidns*) ROOTS="$ROOTS $tgt" ;; esac
            continue
            ;;
        man|tree|0[0-7][0-7][0-7]) ;;
        *) die "bad kind '$kind' in '$e' (a mode such as 0555, man, tree, owndir)" ;;
    esac
    if [ "$ACTION" = uninstall ]; then
        if [ "$kind" = tree ] && { [ -e "$DEST$tgt" ] || [ -L "$DEST$tgt" ]; }; then
            { [ ! -L "$DEST$tgt" ] && [ -d "$DEST$tgt" ]; } || die "$DEST$tgt is not a directory (a symbolic link?): nothing is removed"
            odd=$(find "$DEST$tgt" ! -type f ! -type d)
            [ -z "$odd" ] || die "$DEST$tgt holds what install never puts there (a symbolic link?): nothing is removed: $(echo "$odd" | head -3 | tr '\n' ' ')"
        fi
        continue
    fi
    if [ "$kind" = tree ]; then
        if [ ! -d "$src" ]; then
            MISSING="$MISSING $src"
            HINTS="$HINTS
  $src: $(hint "$src")"
            continue
        fi
        bad=$(cd "$src" && find . -type d -name .bin -prune -o ! -type f ! -type d -print)
        [ -z "$bad" ] || die "$src holds something that is neither a regular file nor a directory: $(echo "$bad" | head -3 | tr '\n' ' ')"
        badname=$(tree_files "$src" | grep '[^A-Za-z0-9_./+@-]' | head -1) || true
        [ -z "$badname" ] || die "a file name in $src holds a character that is not allowed: $badname"
    elif [ ! -f "$src" ]; then
        MISSING="$MISSING $src"
        HINTS="$HINTS
  $src: $(hint "$src")"
    fi
done
[ -z "$MISSING" ] || die "nothing was installed: missing$MISSING; build first:$(printf '%s\n' "$HINTS" | awk 'NF && !seen[$0]++ { printf "\n%s", $0 }')"

# 2. install or remove
for e in "$@"; do
    kind=${e%%:*}
    rest=${e#*:}
    src=${rest%%:*}
    tgt=${rest#*:}
    case $kind in
        owndir) ;;
        man)
            if [ "$ACTION" = install ]; then
                if [ $GZ = yes ]; then
                    TMPF=$(mktemp "${TMPDIR:-/tmp}/karidns_man.XXXXXX")
                    gzip -9 -n -c "$src" > "$TMPF" || die "gzip $src failed"
                    put 0444 "$TMPF" "$tgt.gz"
                    rm -f "$TMPF"
                    TMPF=
                else
                    put 0444 "$src" "$tgt"
                fi
            else
                rm -f "$DEST$tgt" "$DEST$tgt.gz"
                rmdirs "$DEST$(dirname "$tgt")"
            fi
            ;;
        tree)
            if [ "$ACTION" = install ]; then
                for f in $(tree_files "$src"); do put 0444 "$src/$f" "$tgt/$f"; done
            elif [ -d "$DEST$tgt" ]; then
                find "$DEST$tgt" -type f -exec rm -f {} +
                find "$DEST$tgt" -depth -type d -exec rmdir {} +
                rmdirs "$DEST$(dirname "$tgt")"
            fi
            ;;
        *)
            if [ "$ACTION" = install ]; then
                put "$kind" "$src" "$tgt"
            else
                rm -f "$DEST$tgt"
                rmdirs "$DEST$(dirname "$tgt")"
            fi
            ;;
    esac
done
exit 0

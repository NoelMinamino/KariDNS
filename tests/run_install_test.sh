#!/bin/sh
# run_install_test.sh - make install / make uninstall and the packages that stage through them (0.7; the Makefile "Installation",
# packaging/install.sh, tests/install_manifest.txt, docs/building.md "Installing").  In a scratch copy of the tree (the binaries that are built
# in it are copied along; nothing is built or installed outside the scratch directory):
#   1. for each make there is (make, and gmake where it is installed): ./configure, then make install (plus install-signer, install-webadmin and
#      their pages and manuals, with a node_modules of the test) into a DESTDIR: the staged tree is exactly tests/install_manifest.txt for the
#      components whose binaries are built (server and db need theirs; dag alone where only dag is built), with the modes of the manifest and the
#      contents of the sources; the database SQL files are those of the drivers config.mk names (4 for sqlite3, 7 for postgresql); node_modules/.bin
#      is left out;
#   2. a second make install changes nothing, a karidns.conf that was there is left as it is, and make uninstall removes every file it installed
#      and the directories of KariDNS, but not that karidns.conf and its directory, and every other directory it made (bin, share/man/man8, ...)
#      is still there;
#   3. ./configure --prefix=/opt/karidns-0.7, --sysconfdir and --libexecdir below it move every file (nothing is left under /usr/local), and
#      uninstall removes the directories of KariDNS only: /opt/karidns-0.7/bin, the prefix itself, ... stay although their path holds "karidns";
#   4. MANCOMPRESS=yes installs every page as NAME.gz with the bytes of man/NAME, BINMODE=0755 changes the mode of the programs only;
#   5. install.sh refuses a relative DESTDIR, a file that is not built (nothing at all is installed then, also when only the last file is missing,
#      and the message names the make target), a symbolic link and a name with a space in a tree; a page that cannot be put leaves no temporary
#      file; uninstall of a tree removes what is installed even when the source tree is gone or has changed since (npm ci with another lock), and
#      refuses an installed tree with a symbolic link before it removes anything; as root the files belong to 0:0;
#   6. the documented sequence (docs/building.md "INSTALLING"): ./configure; make; with database drivers make install stops before it installs
#      anything and names make karidns-dbloader karidns-zone; after that make install installs the manifest; the build is a copy of the sources
#      compiled by a stub compiler (CC=, which writes each -o file), so that nothing real is compiled;
#   7. (FreeBSD with pkg) build_pkg.sh --no-build, for karidns and for the database package of the drivers the built loader has, lists exactly the
#      files make install stages for its targets, with the same modes and root:wheel, also when the environment sets BINDIR, MANDIR, BINMODE,
#      ... (pkg_stage passes every one); conflicts with the three other server packages, provides karicheck (and karidns-zone), creates the user
#      karidns before it installs and /var/run/karidns after (not /var/log/named: the rc script makes it for the user of the configuration);
#      with npm, node24 and bind-tools the signer and WebAdmin packages likewise (their requires); no user is created here: no package is
#      installed.
# SKIP: the server / db / dag components whose binaries are not built (build them first: make all karidns-dbloader karidns-zone); part 7 without
# pkg, without a database package for the built loader (drivers neither sqlite3, postgresql nor both) and for the Node packages without npm,
# node24 or bind-tools.  Environment: KEEP=1 keeps the scratch directory.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -15 | sed 's/^/         /'; }
note() { echo "  [SKIP] $1"; }
done_() { echo; echo "=== run_install_test: $FAILS failed, $PASS passed ==="; [ "$FAILS" = 0 ]; exit $?; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_install.XXXXXX") || exit 1
cleanup() { if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else chmod -R u+rwX "$T" 2>/dev/null; rm -rf "$T"; fi; }
trap cleanup EXIT
trap 'exit 130' INT TERM
OS=$(uname -s)
fmode() { if [ "$OS" = FreeBSD ] || [ "$OS" = Darwin ]; then stat -f %Lp "$1"; else stat -c %a "$1"; fi; }
fown() { if [ "$OS" = FreeBSD ] || [ "$OS" = Darwin ]; then stat -f '%u:%g' "$1"; else stat -c '%u:%g' "$1"; fi; }

# --- the scratch tree: what make install reads, and the binaries that are built ----------------------------------------------------------
S=$T/src
mkdir -p "$S/signer" "$S/webadmin" "$S/node"
cp Makefile configure VERSION LICENSE README.md ./*.sample "$S/"
cp -R man docs db packaging "$S/"
cp -R signer/bin signer/lib signer/package.json signer/package-lock.json "$S/signer/"
cp -R webadmin/bin webadmin/lib webadmin/ui webadmin/package.json webadmin/package-lock.json "$S/webadmin/"
cp -R node/lib node/package.json "$S/node/"
COMPS=""
SERVER_BINS="karidns karictl karicheck karidns-tapstat"
have() { for b in "$@"; do [ -x "$b" ] || return 1; done; }
if have $SERVER_BINS dag; then COMPS="server dag"; cp -p $SERVER_BINS dag "$S/"; elif have dag; then COMPS="dag"; cp -p dag "$S/"; fi
[ -n "$COMPS" ] || { echo "SKIP: neither the server nor dag is built (make all)"; exit 0; }
case " $COMPS " in *" server "*) ;; *) note "the server is not built: only dag is installed (make all for the rest)" ;; esac
HAVE_DB=no
if have karidns-dbloader karidns-zone; then HAVE_DB=yes; cp -p karidns-dbloader karidns-zone "$S/"; else note "karidns-dbloader / karidns-zone are not built: no database parts"; fi
# a node_modules of the test (npm is not needed to check where it goes): a package, a nested directory and the .bin of npm, which is left out
for p in signer webadmin; do
    mkdir -p "$S/$p/node_modules/pg/lib" "$S/$p/node_modules/.bin"
    echo '{ "name": "pg", "version": "0.0.0-test" }' > "$S/$p/node_modules/pg/package.json"
    echo 'module.exports = {};' > "$S/$p/node_modules/pg/lib/index.js"
    ln -s ../pg/lib/index.js "$S/$p/node_modules/.bin/pg"
done
cd "$S" || exit 1
rm -f config.mk

# expected PREFIX SYSCONFDIR LIBEXECDIR GZ BINMODE COMPONENT...: "MODE PATH SOURCE" of the manifest for these components, trees expanded
expected() {
    _p=$1 _s=$2 _l=$3 _gz=$4 _bm=$5
    shift 5
    _want=" $* "
    tr -d '\r' < "$ROOT/tests/install_manifest.txt" | while read -r c m path src; do
        case $c in ''|'#'*) continue ;; esac
        case $_want in *" $c "*) ;; *) continue ;; esac
        path=$(printf '%s' "$path" | sed -e "s|\${PREFIX}|$_p|g" -e "s|\${SYSCONFDIR}|$_s|g" -e "s|\${LIBEXECDIR}|$_l|g")
        case $c in man-*) [ -n "$src" ] || src=man/${path##*/} ;; esac
        [ -n "$src" ] || src=${path##*/}
        if [ "$m" = tree ]; then
            (cd "$src" && find . -type d -name .bin -prune -o -type f -print) | sed 's|^\./||' | while read -r f; do echo "0444 $path/$f $src/$f"; done
            continue
        fi
        [ "$m" = 0555 ] && m=$_bm
        case $c in man-*) [ "$_gz" = yes ] && path=$path.gz ;; esac
        echo "$m $path $src"
    done | LC_ALL=C sort -k2
}
# staged DIR: "MODE PATH" of every file under DIR (a symbolic link or anything else is shown as such)
staged() {
    (cd "$1" && find . ! -type d) | sed 's|^\.||' | LC_ALL=C sort | while read -r f; do
        if [ -L "$1$f" ] || [ ! -f "$1$f" ]; then echo "notafile $f"; else printf '%04d %s\n' "$(fmode "$1$f")" "$f"; fi
    done
}
# compare LABEL STAGE EXPECTED-FILE: the staged tree is the expected one, and every file has the bytes of its source
compare() {
    staged "$2" > "$T/got"
    awk '{ print $1, $2 }' "$3" > "$T/want"
    if cmp -s "$T/got" "$T/want"; then ok "$1: the staged tree is the manifest ($(wc -l < "$T/want" | tr -d ' ') files, modes included)"; else bad "$1: the staged tree differs from the manifest (< staged, > manifest)" "$(diff "$T/got" "$T/want")"; fi
    _bad=""
    while read -r m path src; do
        [ -f "$2$path" ] || continue
        case $path in
            *.gz) gunzip -c "$2$path" | cmp -s - "$src" || _bad="$_bad $path" ;;
            *) cmp -s "$2$path" "$src" || _bad="$_bad $path" ;;
        esac
    done < "$3"
    [ -z "$_bad" ] && ok "$1: every file has the bytes of its source" || bad "$1: files that differ from their source:$_bad"
}
# roots PREFIX SYSCONFDIR LIBEXECDIR: the directories of KariDNS (INST_OWN of the Makefile)
roots() { echo "$2/karidns $1/share/karidns $1/share/doc/karidns $3/karidns-signer $3/karidns-webadmin"; }
# leftovers STAGE ROOT...: the files left, and the directories left at or below a root
leftovers() {
    _st=$1; shift
    (cd "$_st" && find . ! -type d) | sed 's|^\.||'
    for _r in "$@"; do [ -d "$_st$_r" ] && (cd "$_st" && find ".$_r" -type d) | sed 's|^\.||'; done
}
# stddirs STAGED-LIST ROOT...: the directories of the installed files and their parents that are not at or below a root (bin, share/man/man8, ...)
stddirs() {
    _l=$1; shift
    awk '{ print $2 }' "$_l" | while read -r _p; do _d=${_p%/*}; while [ -n "$_d" ]; do echo "$_d"; _d=${_d%/*}; done; done | LC_ALL=C sort -u | while read -r _d; do
        _m=no
        for _r in "$@"; do case $_d in "$_r"|"$_r"/*) _m=yes ;; esac; done
        [ $_m = no ] && echo "$_d"
    done
}
# kept LABEL STAGE STAGED-LIST ROOT...: after uninstall, every directory of stddirs is still there (and there are some)
kept() {
    _lb=$1 _st=$2 _sl=$3; shift 3
    _dirs=$(stddirs "$_sl" "$@"); _gone=""
    for _d in $_dirs; do [ -d "$_st$_d" ] || _gone="$_gone $_d"; done
    if [ -z "$_dirs" ]; then bad "$_lb: no directory outside those of KariDNS to check"; elif [ -z "$_gone" ]; then ok "$_lb: the $(echo "$_dirs" | wc -l | tr -d ' ') other directories it made stay ($(echo "$_dirs" | grep -E '/(bin|man8)$' | tr '\n' ' '))"; else bad "$_lb: uninstall removed directories that are not KariDNS's:$_gone"; fi
}

DRV() { sed -n 's/^DB_DRIVERS = //p' config.mk; }
db_comps() { _c=""; if [ $HAVE_DB = yes ]; then _c="db man-db docs-db"; for d in $(DRV); do _c="$_c $d"; done; fi; echo "$_c"; }
# the number of SQL files of the drivers of config.mk
nsql() { _n=0; for d in $(DRV); do case $d in sqlite3) _n=$((_n + 4)) ;; postgresql) _n=$((_n + 7)) ;; esac; done; echo $_n; }
all_comps() {
    _c="$COMPS"
    for x in $COMPS; do _c="$_c man-$x docs-$x"; done
    echo "$_c signer webadmin man-signer man-webadmin docs-signer docs-webadmin $(db_comps)"
}
EXTRA="install-signer install-webadmin install-man-signer install-man-webadmin install-docs-signer install-docs-webadmin"
UNEXTRA="uninstall-signer uninstall-webadmin uninstall-man-signer uninstall-man-webadmin uninstall-docs-signer uninstall-docs-webadmin"
if [ "$COMPS" = dag ]; then INST="install-dag install-man-dag install-docs-dag"; UNINST="uninstall-dag uninstall-man-dag uninstall-docs-dag"; else INST=install; UNINST=uninstall; fi
WITH_DRV=$( [ $HAVE_DB = yes ] && "$ROOT/karidns-dbloader" --drivers | tr '\n' ' ' || echo none)

MAKES=""
for mk in make gmake; do command -v $mk > /dev/null 2>&1 && MAKES="$MAKES $mk"; done
# BSD make and GNU make are told apart by --version (GNU make only); "make" may be either
for MK in $MAKES; do
    if [ "$MK" = gmake ] && make --version 2>/dev/null | grep -q 'GNU Make'; then continue; fi
    kind=$($MK --version 2>/dev/null | grep -q 'GNU Make' && echo "GNU make" || echo "BSD make")
    echo "-- $kind ($MK): the default directories"
    rm -f config.mk config.log
    sh ./configure --with-db-drivers="$WITH_DRV" > "$T/cfg.out" 2>&1 || { bad "./configure failed" "$(tail -5 "$T/cfg.out")"; continue; }
    D=$T/stage-$MK
    # shellcheck disable=SC2086
    if $MK $INST $EXTRA DESTDIR="$D" MANCOMPRESS=no > "$T/inst.out" 2>&1; then ok "$MK $INST $EXTRA (DESTDIR, MANCOMPRESS=no)"; else bad "$MK install failed" "$(tail -10 "$T/inst.out")"; continue; fi
    # shellcheck disable=SC2046
    expected /usr/local /usr/local/etc /usr/local/libexec no 0555 $(all_comps) > "$T/exp"
    compare "$MK, default directories" "$D" "$T/exp"
    grep -q '/node_modules/\.bin' "$T/got" && bad "node_modules/.bin was installed" || ok "node_modules/.bin is left out"
    if [ $HAVE_DB = yes ]; then
        n=$(grep -c ' /usr/local/share/karidns/db/' "$T/got"); w=$(nsql)
        if [ "$n" -gt 0 ] && [ "$n" = "$w" ]; then ok "the SQL files of the drivers of config.mk ($(DRV)): $n"; else bad "SQL files of the drivers ($(DRV)): $n installed, $w wanted"; fi
    fi
    staged "$D" > "$T/first"
    # a configuration that is there before is never touched, and stays after uninstall
    mkdir -p "$D/usr/local/etc/karidns"
    echo 'options { port 5353; };' > "$D/usr/local/etc/karidns/karidns.conf"
    # shellcheck disable=SC2086
    $MK $INST $EXTRA DESTDIR="$D" MANCOMPRESS=no > "$T/inst2.out" 2>&1 || bad "the second make install failed" "$(tail -5 "$T/inst2.out")"
    staged "$D" | grep -v ' /usr/local/etc/karidns/karidns.conf$' > "$T/second"
    cmp -s "$T/first" "$T/second" && ok "a second make install leaves the same tree" || bad "the second make install changed the tree" "$(diff "$T/first" "$T/second")"
    [ "$(cat "$D/usr/local/etc/karidns/karidns.conf")" = 'options { port 5353; };' ] && ok "...and an existing karidns.conf as it was (only *.sample is installed)" || bad "karidns.conf was changed"
    # shellcheck disable=SC2086
    if $MK $UNINST $UNEXTRA DESTDIR="$D" > "$T/un.out" 2>&1; then ok "$MK $UNINST $UNEXTRA"; else bad "$MK uninstall failed" "$(tail -10 "$T/un.out")"; fi
    # shellcheck disable=SC2046
    left=$(leftovers "$D" $(roots /usr/local /usr/local/etc /usr/local/libexec))
    [ "$left" = "/usr/local/etc/karidns/karidns.conf
/usr/local/etc/karidns" ] && ok "uninstall removes every file it installed and the directories of KariDNS, but not karidns.conf and its directory" || bad "uninstall left (or removed) other things" "$left"
    # shellcheck disable=SC2046
    kept "$MK uninstall" "$D" "$T/first" $(roots /usr/local /usr/local/etc /usr/local/libexec)
    rm -rf "$D"

    echo "-- $kind ($MK): --prefix=/opt/karidns-0.7, --sysconfdir, --libexecdir (a prefix whose name starts with karidns)"
    P7=/opt/karidns-0.7
    sh ./configure --prefix=$P7 --sysconfdir=$P7/etc --libexecdir=$P7/lib/exec --with-db-drivers="$WITH_DRV" > "$T/cfg.out" 2>&1 || { bad "./configure with the directories failed" "$(tail -5 "$T/cfg.out")"; continue; }
    D=$T/stage2-$MK
    # shellcheck disable=SC2086
    $MK $INST $EXTRA DESTDIR="$D" MANCOMPRESS=no > "$T/inst.out" 2>&1 || { bad "$MK install with the directories failed" "$(tail -10 "$T/inst.out")"; continue; }
    # shellcheck disable=SC2046
    expected $P7 $P7/etc $P7/lib/exec no 0555 $(all_comps) > "$T/exp"
    compare "$MK, other directories" "$D" "$T/exp"
    [ ! -e "$D/usr" ] && ok "nothing is installed under /usr/local" || bad "files under /usr" "$(cd "$D" && find ./usr | head -5)"
    staged "$D" > "$T/first"
    # shellcheck disable=SC2086
    if $MK $UNINST $UNEXTRA DESTDIR="$D" > "$T/un.out" 2>&1; then ok "$MK $UNINST $UNEXTRA (other directories)"; else bad "$MK uninstall with the directories failed" "$(tail -10 "$T/un.out")"; fi
    # shellcheck disable=SC2046
    [ -z "$(leftovers "$D" $(roots $P7 $P7/etc $P7/lib/exec))" ] && ok "...and removes them again" || bad "uninstall left" "$(leftovers "$D" $(roots $P7 $P7/etc $P7/lib/exec))"
    # shellcheck disable=SC2046
    kept "$MK uninstall, prefix $P7" "$D" "$T/first" $(roots $P7 $P7/etc $P7/lib/exec)
    [ -d "$D$P7/bin" ] && [ -d "$D$P7" ] && [ -d "$D$P7/etc" ] && ok "...$P7, $P7/bin and $P7/etc stay" || bad "uninstall removed $P7 or $P7/bin or $P7/etc"
    rm -rf "$D"
done

echo "-- MANCOMPRESS=yes, BINMODE=0755"
rm -f config.mk config.log
sh ./configure --with-db-drivers=none > /dev/null 2>&1
D=$T/stage-gz
if [ "$COMPS" = dag ]; then GZT="install-dag install-man-dag"; GZC="dag man-dag"; else GZT="install-server install-dag install-man-server install-man-dag"; GZC="server dag man-server man-dag"; fi
# shellcheck disable=SC2086
make $GZT DESTDIR="$D" MANCOMPRESS=yes BINMODE=0755 > "$T/inst.out" 2>&1 || bad "make with MANCOMPRESS=yes failed" "$(tail -5 "$T/inst.out")"
# shellcheck disable=SC2086
expected /usr/local /usr/local/etc /usr/local/libexec yes 0755 $GZC > "$T/exp"
compare "MANCOMPRESS=yes BINMODE=0755" "$D" "$T/exp"
# shellcheck disable=SC2086
if make $(echo "$GZT" | sed 's/install-/uninstall-/g') DESTDIR="$D" > "$T/un.out" 2>&1; then ok "uninstall of the compressed pages"; else bad "uninstall of the compressed pages failed" "$(tail -5 "$T/un.out")"; fi
# shellcheck disable=SC2046
[ -z "$(leftovers "$D" $(roots /usr/local /usr/local/etc /usr/local/libexec))" ] && ok "...removes them" || bad "uninstall left" "$(leftovers "$D" $(roots /usr/local /usr/local/etc /usr/local/libexec))"

echo "-- what install.sh refuses, and nothing is installed then"
sh packaging/install.sh install relative/stage 0555:dag:/usr/local/bin/dag > "$T/r.out" 2>&1 && bad "a relative DESTDIR was taken" || { grep -q 'absolute' "$T/r.out" && ok "a relative DESTDIR is refused" || bad "relative DESTDIR: unexpected message" "$(cat "$T/r.out")"; }
sh packaging/install.sh install "$T/r1" 0555:dag:/usr/local/bin/dag 0444:man/dag.1:/usr/local/share/man/man1/dag.1 0555:karidns-dbloader-not-built:/usr/local/libexec/x \
    > "$T/r.out" 2>&1 && bad "a missing file was installed" || { grep -q 'nothing was installed: missing karidns-dbloader-not-built' "$T/r.out" && ok "the last file missing: refused, with the hint" || bad "missing file: unexpected message" "$(cat "$T/r.out")"; }
[ ! -e "$T/r1" ] && ok "...and nothing of the files before it was installed" || bad "a refused install left files" "$(cd "$T/r1" && find . -type f)"
mv karidns-zone karidns-zone.away 2>/dev/null; mv karidns-dbloader karidns-dbloader.away 2>/dev/null
make install DB_DRIVERS=sqlite3 DESTDIR="$T/r1b" > "$T/r.out" 2>&1 && bad "make install with DB_DRIVERS and no loader succeeded" || { grep -q 'karidns-dbloader: make karidns-dbloader karidns-zone' "$T/r.out" && ok "make install with DB_DRIVERS=sqlite3 and no loader: refused, names make karidns-dbloader karidns-zone" || bad "make install without the loader: message" "$(cat "$T/r.out")"; }
[ ! -e "$T/r1b" ] && ok "...before the server, dag, the pages or the manuals are installed" || bad "make install without the loader left files" "$(cd "$T/r1b" && find . -type f | head -5)"
mv karidns-zone.away karidns-zone 2>/dev/null; mv karidns-dbloader.away karidns-dbloader 2>/dev/null
mv man/dag.1 man/dag.1.away
make install-dag install-man-dag DESTDIR="$T/r1c" > "$T/r.out" 2>&1; mv man/dag.1.away man/dag.1
grep -q 'man/dag.1: make man' "$T/r.out" && [ ! -e "$T/r1c/usr/local/share/man" ] && ok "a missing page: install-man-dag refuses it and says make man" || bad "a missing page" "$(cat "$T/r.out")"
mkdir -p "$T/badtree/a" && echo x > "$T/badtree/a/f" && ln -s f "$T/badtree/a/link"
sh packaging/install.sh install "$T/r2" "tree:$T/badtree:/usr/local/libexec/karidns-x" > "$T/r.out" 2>&1 && bad "a symbolic link in a tree was installed" || ok "a symbolic link in a tree is refused ($(head -1 "$T/r.out" | cut -c1-80))"
rm -f "$T/badtree/a/link" && echo y > "$T/badtree/a/with space"
sh packaging/install.sh install "$T/r3" "tree:$T/badtree:/usr/local/libexec/karidns-x" > "$T/r.out" 2>&1 && bad "a name with a space was installed" || ok "a name with a space in a tree is refused"
[ ! -e "$T/r2" ] && [ ! -e "$T/r3" ] && ok "...before anything of that tree is installed" || bad "a refused tree left files"
sh packaging/install.sh install "$T/r4" "0555:dag:/usr/local/bin/a b" > "$T/r.out" 2>&1 && bad "a target with a space was taken" || ok "a target with a space is refused"
# a page that cannot be put (a file where its directory should be): no temporary file is left
mkdir -p "$T/tmpd" "$T/r6/usr/local/share" && : > "$T/r6/usr/local/share/man"
TMPDIR=$T/tmpd MANCOMPRESS=yes sh packaging/install.sh install "$T/r6" man:man/dag.1:/usr/local/share/man/man1/dag.1 > "$T/r.out" 2>&1 && bad "a page was put below a file"
[ -z "$(ls "$T/tmpd")" ] && ok "a page that cannot be put leaves no temporary file" || bad "temporary files left: $(ls "$T/tmpd")"
# uninstall of a tree: the installed directory, not the source tree as it is now
mkdir -p "$T/nm/pg/lib" && echo a > "$T/nm/pg/lib/a.js" && echo b > "$T/nm/pg/lib/b.js"
TREE="tree:$T/nm:/usr/local/libexec/karidns-signer/node_modules"
OWNS="owndir:-:/usr/local/libexec/karidns-signer"
sh packaging/install.sh install "$T/u1" "$OWNS" "$TREE" > /dev/null 2>&1
mv "$T/nm" "$T/nm.away"
if sh packaging/install.sh uninstall "$T/u1" "$OWNS" "$TREE" > "$T/r.out" 2>&1 && [ ! -e "$T/u1/usr/local/libexec/karidns-signer" ] && [ -d "$T/u1/usr/local/libexec" ]; then ok "uninstall of a tree whose source is gone removes it (and its KariDNS directory, not libexec)"; else bad "uninstall of a tree without its source" "$(cat "$T/r.out"; cd "$T/u1" 2>/dev/null && find .)"; fi
mv "$T/nm.away" "$T/nm"
sh packaging/install.sh install "$T/u2" "$OWNS" "$TREE" > /dev/null 2>&1
rm "$T/nm/pg/lib/a.js" && echo c > "$T/nm/pg/lib/c.js"
if sh packaging/install.sh uninstall "$T/u2" "$OWNS" "$TREE" > "$T/r.out" 2>&1 && [ ! -e "$T/u2/usr/local/libexec/karidns-signer" ]; then ok "...and one whose source changed since (npm ci with another lock): no stale file"; else bad "uninstall of a changed tree" "$(cat "$T/r.out"; cd "$T/u2" && find . -type f)"; fi
sh packaging/install.sh install "$T/u3" "$OWNS" "$TREE" > /dev/null 2>&1
ln -s /etc "$T/u3/usr/local/libexec/karidns-signer/node_modules/pg/escape"
sh packaging/install.sh uninstall "$T/u3" "$OWNS" "$TREE" > "$T/r.out" 2>&1 && bad "uninstall of a tree with a symbolic link succeeded" || { [ -f "$T/u3/usr/local/libexec/karidns-signer/node_modules/pg/lib/b.js" ] && ok "an installed tree with a symbolic link: refused, nothing removed" || bad "a tree with a symbolic link: files were removed" "$(cat "$T/r.out")"; }
rm -f "$T/u3/usr/local/libexec/karidns-signer/node_modules/pg/escape"
mv "$T/u3/usr/local/libexec/karidns-signer/node_modules" "$T/u3/nm-real" && ln -s "$T/u3/nm-real" "$T/u3/usr/local/libexec/karidns-signer/node_modules"
sh packaging/install.sh uninstall "$T/u3" "$OWNS" "$TREE" > "$T/r.out" 2>&1 && bad "uninstall of a tree that is a symbolic link succeeded" || { [ -f "$T/u3/nm-real/pg/lib/b.js" ] && ok "an installed tree that is a symbolic link: refused, nothing removed through it" || bad "a tree that is a symbolic link: files were removed"; }
if [ "$(id -u)" = 0 ]; then
    make install-dag DESTDIR="$T/r5" > /dev/null 2>&1
    [ "$(fown "$T/r5/usr/local/bin/dag")" = 0:0 ] && ok "as root the files belong to 0:0" || bad "as root: owner $(fown "$T/r5/usr/local/bin/dag")"
else
    note "not root: the owner 0:0 of an install as root"
fi

echo "-- the documented sequence: ./configure; make; make karidns-dbloader karidns-zone (with DB drivers); make install"
B=$T/build
mkdir -p "$B"
(cd "$ROOT" && cp Makefile configure VERSION LICENSE README.md ./*.sample ./*.c ./*.h "$B/" && cp -R tools man docs db packaging "$B/") || bad "copying the sources"
cat > "$T/cc" <<'EOF'
#!/bin/sh
# a compiler stub: writes the file of -o (an executable script), compiles nothing
out=a.out
while [ $# -gt 0 ]; do [ "$1" = -o ] && [ $# -gt 1 ] && { out=$2; shift; }; shift; done
printf '#!/bin/sh\necho stub\n' > "$out" && chmod 755 "$out"
EOF
chmod 755 "$T/cc"
cd "$B" || exit 1
if sh ./configure > "$T/cfg.out" 2>&1 && make CC="$T/cc" > "$T/mk.out" 2>&1; then ok "./configure; make (stub compiler): $(for b in $SERVER_BINS dag; do [ -x "$b" ] && printf '%s ' "$b"; done)"; else bad "./configure; make" "$(tail -5 "$T/cfg.out" "$T/mk.out")"; fi
BDRV=$(sed -n 's/^DB_DRIVERS = //p' config.mk)
D=$T/stage-doc
if [ -n "$BDRV" ]; then
    make install DESTDIR="$D" MANCOMPRESS=no > "$T/i.out" 2>&1 && bad "make install with DB drivers ($BDRV) and no loader succeeded" || { grep -q 'make karidns-dbloader karidns-zone' "$T/i.out" && [ ! -e "$D" ] && ok "make install (DB drivers $BDRV, the loader not built): stops before anything is installed, names make karidns-dbloader karidns-zone" || bad "make install without the loader" "$(cat "$T/i.out")"; }
    make karidns-dbloader karidns-zone CC="$T/cc" > "$T/mk.out" 2>&1 || bad "make karidns-dbloader karidns-zone" "$(tail -5 "$T/mk.out")"
    DOCC="server dag man-server man-dag docs-server docs-dag db man-db docs-db $BDRV"
else
    note "./configure found no DB drivers: the step make karidns-dbloader karidns-zone"
    DOCC="server dag man-server man-dag docs-server docs-dag"
fi
if make install DESTDIR="$D" MANCOMPRESS=no > "$T/i.out" 2>&1; then ok "make install"; else bad "make install after the documented steps failed" "$(cat "$T/i.out")"; fi
# shellcheck disable=SC2086
(cd "$S" && expected /usr/local /usr/local/etc /usr/local/libexec no 0555 $DOCC) > "$T/exp"
# the programs are the stubs of this build, not those of the tree: compared by name and mode only
staged "$D" > "$T/got"; awk '{ print $1, $2 }' "$T/exp" > "$T/want"
cmp -s "$T/got" "$T/want" && ok "...installs the manifest of the server, dag$( [ -n "$BDRV" ] && echo ", the database parts ($BDRV)") ($(wc -l < "$T/want" | tr -d ' ') files)" || bad "the documented sequence installs another tree (< staged, > manifest)" "$(diff "$T/got" "$T/want")"
cd "$S" || exit 1

echo "-- the FreeBSD packages list what make install stages"
if ! command -v pkg > /dev/null 2>&1 || [ "$OS" != FreeBSD ]; then note "no pkg (not FreeBSD): the packages"; done_; fi
case " $COMPS " in *" server "*) ;; *) note "the server is not built: the packages"; done_ ;; esac
# pkgcheck LABEL PKGFILE STAGE: the files of the package (pkg info -l), their modes and owners (tar -tv) are the staged tree
pkgcheck() {
    pkg info -l -F "$2" 2> /dev/null | tail -n +2 | sed 's/^[[:space:]]*//' | LC_ALL=C sort > "$T/pl"
    (cd "$3" && find . -type f) | sed 's|^\.||' | LC_ALL=C sort > "$T/sl"
    if [ ! -s "$T/sl" ]; then bad "$1: the comparison stage is empty"; return; fi
    cmp -s "$T/pl" "$T/sl" && ok "$1: pkg info -l is the staged tree ($(wc -l < "$T/pl" | tr -d ' ') files)" || bad "$1: the package list differs from the stage (< package, > stage)" "$(diff "$T/pl" "$T/sl")"
    tar -tvf "$2" 2> /dev/null | awk '$NF !~ /^\+/ { print $1, $3, $4, $NF }' | LC_ALL=C sort -k4 > "$T/pt"
    # the mode of the stage as tar -tv shows it (0555 -> -r-xr-xr-x), the owner root:wheel
    staged "$3" | awk '{ s = "-"; for (i = 2; i <= 4; i++) { d = substr($1, i, 1) + 0; s = s ((d >= 4) ? "r" : "-") ((d % 4 >= 2) ? "w" : "-") ((d % 2) ? "x" : "-") } print s, "root", "wheel", $2 }' | LC_ALL=C sort -k4 > "$T/st"
    cmp -s "$T/pt" "$T/st" && ok "$1: every file has the mode of the stage and root:wheel" || bad "$1: modes or owners differ (< package, > stage)" "$(diff "$T/pt" "$T/st")"
}
# the variables the Makefile takes from the environment (?=): pkg_stage must not let them change a package
HOSTILE_ENV="PREFIX=/x SYSCONFDIR=/x/etc LIBEXECDIR=/x/libexec BINDIR=/x/bin SBINDIR=/x/sbin MANDIR=/x/man DOCDIR=/x/doc DATADIR=/x/data RCDIR=/x/rc BINMODE=0777 MANCOMPRESS=no"
P=$T/pkg
mkdir -p "$P/out"
cp -Rp "$S/." "$P/src"
cd "$P/src" || exit 1
rm -rf signer/node_modules webadmin/node_modules
# shellcheck disable=SC2086
if (env $HOSTILE_ENV ALLOW_PORTS_OPENSSL=1 sh packaging/freebsd/build_pkg.sh --no-build 9.9.9 "$P/out") > "$T/b.out" 2>&1; then ok "build_pkg.sh --no-build builds karidns (with BINDIR, MANDIR, BINMODE, ... set in the environment)"; else bad "build_pkg.sh --no-build failed" "$(tail -10 "$T/b.out")"; done_; fi
make install-server install-dag install-man-server install-man-dag install-docs-server install-docs-dag DESTDIR="$P/s1" PREFIX=/usr/local MANCOMPRESS=yes > /dev/null 2>&1
pkgcheck karidns "$(ls "$P"/out/karidns-9.9.9-*.pkg)" "$P/s1"
mkdir -p "$P/m1" && tar -xf "$P"/out/karidns-9.9.9-*.pkg -C "$P/m1" +MANIFEST
M=$P/m1/+MANIFEST
grep -q 'pw groupshow karidns >/dev/null 2>&1 || pw groupadd karidns' "$M" && grep -q 'pw useradd karidns -g karidns -h - -d /nonexistent -s /usr/sbin/nologin' "$M" && ok "pre-install creates the group and the user karidns (no login, no home)" || bad "pre-install: no user karidns"
grep -q 'install -d -o root -g wheel -m 0755 /var/run/karidns' "$M" && ok "post-install makes /var/run/karidns" || bad "post-install: no /var/run/karidns"
grep -o '"post-install":"[^"]*"' "$M" | grep -q 'log/named' && bad "post-install makes /var/log/named (the rc script makes it, for the user of the configuration)" || ok "...and leaves /var/log/named to the rc script"
pkg info -R -F "$P"/out/karidns-9.9.9-*.pkg > "$T/raw" 2> /dev/null
for c in karidns-sqlite3 karidns-postgresql karidns-db; do grep -q "\"$c\"" "$T/raw" || bad "karidns does not conflict with $c"; done
sed -n '/^conflicts/,/]/p' "$T/raw" | grep -q '"karidns"' && bad "karidns conflicts with itself" || ok "karidns conflicts with the three database packages"
sed -n '/^provides/,/]/p' "$T/raw" | grep -q '"karicheck"' && ! sed -n '/^provides/,/]/p' "$T/raw" | grep -q karidns-zone && ok "...provides karicheck, not karidns-zone" || bad "provides of karidns" "$(sed -n '/^provides/,/]/p' "$T/raw")"
grep -q 'type: "remove"' "$T/raw" && grep -q 'pw userdel karidns' "$T/raw" && ok "...and says on removal that the user karidns is left" || bad "no removal message"
case $("$ROOT/karidns-dbloader" --drivers 2> /dev/null | tr '\n' ' ') in
    "sqlite3 ") V=sqlite3; N=karidns-sqlite3 ;;
    "postgresql ") V=postgresql; N=karidns-postgresql ;;
    "sqlite3 postgresql ") V=both; N=karidns-db ;;
    *) V="" ;;
esac
if [ $HAVE_DB = yes ] && [ -n "$V" ]; then
    DRVS=$("$ROOT/karidns-dbloader" --drivers | tr '\n' ' ' | sed 's/ $//')
    # shellcheck disable=SC2086
    if (env $HOSTILE_ENV ALLOW_PORTS_OPENSSL=1 sh packaging/freebsd/build_pkg.sh --db $V --no-build 9.9.9 "$P/out") > "$T/b.out" 2>&1; then ok "build_pkg.sh --db $V --no-build builds $N"; else bad "build_pkg.sh --db $V failed" "$(tail -10 "$T/b.out")"; fi
    make install-server install-dag install-man-server install-man-dag install-docs-server install-docs-dag install-db install-man-db install-docs-db \
        DB_DRIVERS="$DRVS" DESTDIR="$P/s2" PREFIX=/usr/local MANCOMPRESS=yes > /dev/null 2>&1
    pkgcheck "$N" "$(ls "$P"/out/$N-9.9.9-*.pkg)" "$P/s2"
    pkg info -R -F "$P"/out/$N-9.9.9-*.pkg > "$T/raw" 2> /dev/null
    sed -n '/^provides/,/]/p' "$T/raw" | grep -q '"karidns-zone"' && ok "$N provides karidns-zone" || bad "$N does not provide karidns-zone"
    sed -n '/^conflicts/,/]/p' "$T/raw" | grep -q '"karidns"' && ! sed -n '/^conflicts/,/]/p' "$T/raw" | grep -q "\"$N\"" && ok "$N conflicts with karidns and not with itself" || bad "conflicts of $N" "$(sed -n '/^conflicts/,/]/p' "$T/raw")"
else
    note "the built loader has no drivers of a package: the database package"
fi
for p in node24 bind-tools; do pkg query '%n' "$p" > /dev/null 2>&1 || { note "$p is not installed: the signer and WebAdmin packages"; done_; }; done
command -v npm > /dev/null 2>&1 || { note "npm is not installed: the signer and WebAdmin packages"; done_; }
export npm_config_prefer_offline=true
for p in signer webadmin; do
    # shellcheck disable=SC2086
    if (env $HOSTILE_ENV sh packaging/freebsd/build_${p}_pkg.sh 9.9.9 "$P/out") > "$T/b.out" 2>&1; then ok "build_${p}_pkg.sh builds karidns-$p"; else bad "build_${p}_pkg.sh failed" "$(tail -10 "$T/b.out")"; continue; fi
    make install-$p install-man-$p install-docs-$p DESTDIR="$P/s-$p" PREFIX=/usr/local MANCOMPRESS=yes > /dev/null 2>&1
    pkgcheck "karidns-$p" "$(ls "$P"/out/karidns-$p-9.9.9-*.pkg)" "$P/s-$p"
    pkg info -R -F "$P"/out/karidns-$p-9.9.9-*.pkg > "$T/raw" 2> /dev/null
    sed -n '/^requires/,/]/p' "$T/raw" | grep -q '"karidns-zone"' && ok "karidns-$p requires karidns-zone" || bad "karidns-$p does not require karidns-zone"
done
done_

#!/bin/sh
# run_install_test.sh - make install / make uninstall and the packages that stage through them (0.7; the Makefile "Installation",
# packaging/install.sh, tests/install_manifest.txt, docs/building.md "Installing").  In a scratch copy of the tree (the binaries that are built
# in it are copied along; nothing is built or installed outside the scratch directory):
#   1. for each make there is (make, and gmake where it is installed): ./configure, then make install (plus install-signer, install-webadmin and
#      their pages and manuals, with a node_modules of the test) into a DESTDIR: the staged tree is exactly tests/install_manifest.txt for the
#      components whose binaries are built (server and db need theirs; dag alone where only dag is built), with the modes of the manifest and the
#      contents of the sources; the database SQL files are those of the drivers config.mk names; node_modules/.bin is left out;
#   2. a second make install changes nothing, a karidns.conf that was there is left as it is, and make uninstall removes every file it installed
#      and the directories of KariDNS, but not that karidns.conf and its directory, and no directory every system has;
#   3. ./configure --prefix, --sysconfdir and --libexecdir that are not the defaults move every file (nothing is left under /usr/local);
#   4. MANCOMPRESS=yes installs every page as NAME.gz with the bytes of man/NAME, BINMODE=0755 changes the mode of the programs only;
#   5. install.sh refuses a relative DESTDIR, a file that is not built (with the hint to build it), a symbolic link and a name with a space in a
#      tree; as root the files belong to 0:0;
#   6. (FreeBSD with pkg) build_pkg.sh --no-build, for karidns and for the database package of the drivers the built loader has, lists exactly the
#      files make install stages for its targets, with the same modes and root:wheel, conflicts with the three other server packages, provides
#      karicheck (and karidns-zone), creates the user karidns before it installs and /var/run/karidns and /var/log/named after; with npm, node24 and
#      bind-tools the signer and WebAdmin packages likewise (their requires); the user is never created here: no package is installed.
# SKIP: the server / db / dag components whose binaries are not built (build them first: make all karidns-dbloader karidns-zone); part 6 without
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
    while read -r c m path src; do
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
    done < "$ROOT/tests/install_manifest.txt" | LC_ALL=C sort -k2
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
# leftovers STAGE: files left, and directories left that belong to KariDNS
leftovers() { (cd "$1" && find . ! -type d; find . -type d | grep '/karidns') | sed 's|^\.||'; }

DRV() { sed -n 's/^DB_DRIVERS = //p' config.mk; }
db_comps() { _c=""; if [ $HAVE_DB = yes ]; then _c="db man-db docs-db"; for d in $(DRV); do _c="$_c $d"; done; fi; echo "$_c"; }
all_comps() {
    _c="$COMPS"
    for x in $COMPS; do _c="$_c man-$x docs-$x"; done
    echo "$_c signer webadmin man-signer man-webadmin docs-signer docs-webadmin $(db_comps)"
}
EXTRA="install-signer install-webadmin install-man-signer install-man-webadmin install-docs-signer install-docs-webadmin"
UNEXTRA="uninstall-signer uninstall-webadmin uninstall-man-signer uninstall-man-webadmin uninstall-docs-signer uninstall-docs-webadmin"
if [ "$COMPS" = dag ]; then INST="install-dag install-man-dag install-docs-dag"; UNINST="uninstall-dag uninstall-man-dag uninstall-docs-dag"; else INST=install; UNINST=uninstall; fi

MAKES=""
for mk in make gmake; do command -v $mk > /dev/null 2>&1 && MAKES="$MAKES $mk"; done
# BSD make and GNU make are told apart by --version (GNU make only); "make" may be either
for MK in $MAKES; do
    if [ "$MK" = gmake ] && make --version 2>/dev/null | grep -q 'GNU Make'; then continue; fi
    kind=$($MK --version 2>/dev/null | grep -q 'GNU Make' && echo "GNU make" || echo "BSD make")
    echo "-- $kind ($MK): the default directories"
    rm -f config.mk config.log
    sh ./configure --with-db-drivers="$( [ $HAVE_DB = yes ] && "$ROOT/karidns-dbloader" --drivers | tr '\n' ' ' || echo none)" > "$T/cfg.out" 2>&1 || { bad "./configure failed" "$(tail -5 "$T/cfg.out")"; continue; }
    D=$T/stage-$MK
    # shellcheck disable=SC2086
    if $MK $INST $EXTRA DESTDIR="$D" MANCOMPRESS=no > "$T/inst.out" 2>&1; then ok "$MK $INST $EXTRA (DESTDIR, MANCOMPRESS=no)"; else bad "$MK install failed" "$(tail -10 "$T/inst.out")"; continue; fi
    # shellcheck disable=SC2046
    expected /usr/local /usr/local/etc /usr/local/libexec no 0555 $(all_comps) > "$T/exp"
    compare "$MK, default directories" "$D" "$T/exp"
    grep -q '/node_modules/\.bin' "$T/got" && bad "node_modules/.bin was installed" || ok "node_modules/.bin is left out"
    if [ $HAVE_DB = yes ]; then
        n=$(grep -c '/share/karidns/db/' "$T/exp"); ok "the SQL files of the drivers of config.mk ($(DRV)): $n"
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
    left=$(leftovers "$D")
    [ "$left" = "/usr/local/etc/karidns/karidns.conf
/usr/local/etc/karidns" ] && ok "uninstall removes every file it installed and the directories of KariDNS, but not karidns.conf and its directory" || bad "uninstall left (or removed) other things" "$left"
    others=$(cd "$D" && find . -type d | sed 's|^\.||' | grep -v '^$' | grep -v '/karidns' | LC_ALL=C sort | tr '\n' ' ')
    ok "the directories left are the ones every system has: $others"
    rm -rf "$D"

    echo "-- $kind ($MK): --prefix, --sysconfdir, --libexecdir"
    sh ./configure --prefix=/opt/kari --sysconfdir=/etc/opt/kari --libexecdir=/opt/kari/lib/exec \
        --with-db-drivers="$( [ $HAVE_DB = yes ] && "$ROOT/karidns-dbloader" --drivers | tr '\n' ' ' || echo none)" > "$T/cfg.out" 2>&1 || { bad "./configure with the directories failed" "$(tail -5 "$T/cfg.out")"; continue; }
    D=$T/stage2-$MK
    # shellcheck disable=SC2086
    $MK $INST $EXTRA DESTDIR="$D" MANCOMPRESS=no > "$T/inst.out" 2>&1 || { bad "$MK install with the directories failed" "$(tail -10 "$T/inst.out")"; continue; }
    # shellcheck disable=SC2046
    expected /opt/kari /etc/opt/kari /opt/kari/lib/exec no 0555 $(all_comps) > "$T/exp"
    compare "$MK, other directories" "$D" "$T/exp"
    [ ! -e "$D/usr" ] && ok "nothing is installed under /usr/local" || bad "files under /usr" "$(cd "$D" && find ./usr | head -5)"
    # shellcheck disable=SC2086
    $MK $UNINST $UNEXTRA DESTDIR="$D" > /dev/null 2>&1
    [ -z "$(leftovers "$D")" ] && ok "...and uninstall removes them again" || bad "uninstall left" "$(leftovers "$D")"
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
make $(echo "$GZT" | sed 's/install-/uninstall-/g') DESTDIR="$D" > /dev/null 2>&1
[ -z "$(leftovers "$D")" ] && ok "uninstall removes the compressed pages" || bad "uninstall left" "$(leftovers "$D")"

echo "-- what install.sh refuses"
sh packaging/install.sh install relative/stage 0555:dag:/usr/local/bin/dag > "$T/r.out" 2>&1 && bad "a relative DESTDIR was taken" || { grep -q 'absolute' "$T/r.out" && ok "a relative DESTDIR is refused" || bad "relative DESTDIR: unexpected message" "$(cat "$T/r.out")"; }
sh packaging/install.sh install "$T/r1" 0555:not-built:/usr/local/bin/x > "$T/r.out" 2>&1 && bad "a missing file was installed" || { grep -q 'is missing (build it first' "$T/r.out" && ok "a file that is not built is refused, with the hint to build it" || bad "missing file: unexpected message" "$(cat "$T/r.out")"; }
mkdir -p "$T/badtree/a" && echo x > "$T/badtree/a/f" && ln -s f "$T/badtree/a/link"
sh packaging/install.sh install "$T/r2" "tree:$T/badtree:/usr/local/libexec/karidns-x" > "$T/r.out" 2>&1 && bad "a symbolic link in a tree was installed" || ok "a symbolic link in a tree is refused ($(head -1 "$T/r.out" | cut -c1-80))"
rm -f "$T/badtree/a/link" && echo y > "$T/badtree/a/with space"
sh packaging/install.sh install "$T/r3" "tree:$T/badtree:/usr/local/libexec/karidns-x" > "$T/r.out" 2>&1 && bad "a name with a space was installed" || ok "a name with a space in a tree is refused"
[ ! -e "$T/r2" ] && [ ! -e "$T/r3" ] && ok "...before anything of that tree is installed" || bad "a refused tree left files"
sh packaging/install.sh install "$T/r4" "0555:dag:/usr/local/bin/a b" > "$T/r.out" 2>&1 && bad "a target with a space was taken" || ok "a target with a space is refused"
if [ "$(id -u)" = 0 ]; then
    make install-dag DESTDIR="$T/r5" > /dev/null 2>&1
    [ "$(fown "$T/r5/usr/local/bin/dag")" = 0:0 ] && ok "as root the files belong to 0:0" || bad "as root: owner $(fown "$T/r5/usr/local/bin/dag")"
else
    note "not root: the owner 0:0 of an install as root"
fi

echo "-- the FreeBSD packages list what make install stages"
if ! command -v pkg > /dev/null 2>&1 || [ "$OS" != FreeBSD ]; then note "no pkg (not FreeBSD): the packages"; done_; fi
case " $COMPS " in *" server "*) ;; *) note "the server is not built: the packages"; done_ ;; esac
# pkgcheck LABEL PKGFILE STAGE: the files of the package (pkg info -l), their modes and owners (tar -tv) are the staged tree
pkgcheck() {
    pkg info -l -F "$2" 2> /dev/null | tail -n +2 | sed 's/^[[:space:]]*//' | LC_ALL=C sort > "$T/pl"
    (cd "$3" && find . -type f) | sed 's|^\.||' | LC_ALL=C sort > "$T/sl"
    cmp -s "$T/pl" "$T/sl" && ok "$1: pkg info -l is the staged tree ($(wc -l < "$T/pl" | tr -d ' ') files)" || bad "$1: the package list differs from the stage (< package, > stage)" "$(diff "$T/pl" "$T/sl")"
    tar -tvf "$2" 2> /dev/null | awk '$NF !~ /^\+/ { print $1, $3, $4, $NF }' | LC_ALL=C sort -k4 > "$T/pt"
    # the mode of the stage as tar -tv shows it (0555 -> -r-xr-xr-x), the owner root:wheel
    staged "$3" | awk '{ s = "-"; for (i = 2; i <= 4; i++) { d = substr($1, i, 1) + 0; s = s ((d >= 4) ? "r" : "-") ((d % 4 >= 2) ? "w" : "-") ((d % 2) ? "x" : "-") } print s, "root", "wheel", $2 }' | LC_ALL=C sort -k4 > "$T/st"
    cmp -s "$T/pt" "$T/st" && ok "$1: every file has the mode of the stage and root:wheel" || bad "$1: modes or owners differ (< package, > stage)" "$(diff "$T/pt" "$T/st")"
}
P=$T/pkg
mkdir -p "$P/out"
cp -Rp "$S/." "$P/src"
cd "$P/src" || exit 1
rm -rf signer/node_modules webadmin/node_modules
if (sh packaging/freebsd/build_pkg.sh --no-build 9.9.9 "$P/out") > "$T/b.out" 2>&1; then ok "build_pkg.sh --no-build builds karidns"; else bad "build_pkg.sh --no-build failed" "$(tail -10 "$T/b.out")"; done_; fi
make install-server install-dag install-man-server install-man-dag install-docs-server install-docs-dag DESTDIR="$P/s1" PREFIX=/usr/local MANCOMPRESS=yes > /dev/null 2>&1
pkgcheck karidns "$(ls "$P"/out/karidns-9.9.9-*.pkg)" "$P/s1"
mkdir -p "$P/m1" && tar -xf "$P"/out/karidns-9.9.9-*.pkg -C "$P/m1" +MANIFEST
M=$P/m1/+MANIFEST
grep -q 'pw groupadd karidns$' "$M" && grep -q 'pw useradd karidns -g karidns -h - -d /nonexistent -s /usr/sbin/nologin' "$M" && ok "pre-install creates the group and the user karidns (no login, no home)" || bad "pre-install: no user karidns"
grep -q 'install -d -o root -g wheel -m 0755 /var/run/karidns' "$M" && grep -q '\[ -d /var/log/named \] || install -d -o karidns -g karidns -m 0755 /var/log/named' "$M" && ok "post-install makes /var/run/karidns and a missing /var/log/named" || bad "post-install: no directories"
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
    if (sh packaging/freebsd/build_pkg.sh --db $V --no-build 9.9.9 "$P/out") > "$T/b.out" 2>&1; then ok "build_pkg.sh --db $V --no-build builds $N"; else bad "build_pkg.sh --db $V failed" "$(tail -10 "$T/b.out")"; fi
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
    if (sh packaging/freebsd/build_${p}_pkg.sh 9.9.9 "$P/out") > "$T/b.out" 2>&1; then ok "build_${p}_pkg.sh builds karidns-$p"; else bad "build_${p}_pkg.sh failed" "$(tail -10 "$T/b.out")"; continue; fi
    make install-$p install-man-$p install-docs-$p DESTDIR="$P/s-$p" PREFIX=/usr/local MANCOMPRESS=yes > /dev/null 2>&1
    pkgcheck "karidns-$p" "$(ls "$P"/out/karidns-$p-9.9.9-*.pkg)" "$P/s-$p"
    pkg info -R -F "$P"/out/karidns-$p-9.9.9-*.pkg > "$T/raw" 2> /dev/null
    sed -n '/^requires/,/]/p' "$T/raw" | grep -q '"karidns-zone"' && ok "karidns-$p requires karidns-zone" || bad "karidns-$p does not require karidns-zone"
done
done_

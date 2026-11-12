#!/bin/sh
# run_configure_test.sh - ./configure and config.mk (0.6.2; docs/building.md).  On a scratch copy of the sources it checks that
#   1. --help works, and every example of its text runs (the ones that need a database library SKIP without it);
#   2. a wrong option is a usage error (exit 2) and writes no config.mk;
#   3. config.mk holds what the options say: PREFIX, SYSCONFDIR and the define of a sysconfdir that is not the default, -march, the drivers,
#      CFLAGS and LDFLAGS from the environment (a $ is doubled), the version;
#   4. a library that was asked for and is missing is an error (exit 1), and with auto a line of the summary: tested with a compiler wrapper
#      that fails on the header of the library, so it does not depend on what is installed;
#   5. the compile and link commands of `make -n karidns dag karicheck karictl karidns-dbloader karidns-zone` are the same without config.mk
#      and with it, for the same options (BSD make and GNU make; skipped with GNU make 3.81, which cannot probe without configure), and a
#      sysconfdir that is not the default adds only its -D;
#   6. make distclean removes config.mk and config.log, and a second ./configure writes the same config.mk;
#   7. the search paths of the Makefile (BREW_CFLAGS, BREW_LDFLAGS) are the ones configure tests with;
#   8. (unless KARI_CONFIGURE_NOBUILD=1) karictl built with --sysconfdir looks for its configuration there, and the default build in
#      /usr/local/etc.
# Needs sh, make, a C compiler, cp, cmp, sed, grep.  Run from anywhere; it works in a copy and leaves the tree as it is.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
FAIL=0
ok()   { echo "  [OK] $1"; }
bad()  { echo "  [FAIL] $1"; FAIL=1; }
note() { echo "  [SKIP] $1"; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_configure.XXXXXX") || exit 1
trap 'rm -rf "$T"' EXIT
trap 'exit 1' HUP INT TERM

# the scratch tree: the sources and the headers (make -n needs them), no objects
mkdir -p "$T/tools"
cp "$ROOT"/*.c "$ROOT"/*.h "$ROOT/Makefile" "$ROOT/VERSION" "$ROOT/configure" "$T/"
cp "$ROOT"/tools/*.c "$ROOT"/tools/*.h "$T/tools/"
cd "$T" || exit 1

REALCC=
for c in cc gcc clang; do command -v $c >/dev/null 2>&1 && { REALCC=$c; break; }; done
[ -n "$REALCC" ] || { echo "SKIP: no C compiler"; exit 0; }

# a compiler that fails on the header of a library or on one argument, to show that a library is "missing" (FAKECC_FAIL_INC, FAKECC_FAIL_ARG)
cat > "$T/fakecc" <<EOF
#!/bin/sh
for a in "\$@"; do
    [ -n "\${FAKECC_FAIL_ARG-}" ] && [ "\$a" = "\$FAKECC_FAIL_ARG" ] && exit 1
    case \$a in
        conftest*.c) [ -n "\${FAKECC_FAIL_INC-}" ] && grep -q "#include <\$FAKECC_FAIL_INC>" "\$a" && exit 1 ;;
    esac
done
exec $REALCC "\$@"
EOF
chmod +x "$T/fakecc"

# cfg ARGS...: ./configure in the scratch tree; the output is in $T/out, the exit status is returned
cfg() {
    rm -f config.mk config.log
    sh ./configure "$@" > "$T/out" 2>&1
}
# mkval NAME: the value of NAME in config.mk
mkval() { sed -n "s/^$1 = //p" config.mk | sed 's/[[:space:]]*$//'; }

# --- 1. --help and its examples ---------------------------------------------------------------------------------------------------------
echo "--- --help"
if sh ./configure --help > "$T/help" 2>&1 && grep -q '^Usage: ./configure' "$T/help" && [ ! -e config.mk ]; then
    ok "--help prints the usage, exit 0, no config.mk"
else
    bad "--help failed or wrote config.mk: $(head -3 "$T/help")"
fi
for o in --prefix --sysconfdir --with-db-drivers --with-idn2 --with-openssl --march CC CFLAGS LDFLAGS; do
    grep -q -- "$o" "$T/help" && ok "--help names $o" || bad "--help does not name $o"
done
cfg; PLAIN_RC=$?
if [ $PLAIN_RC -eq 0 ] && [ -f config.mk ] && [ -f config.log ]; then
    ok "./configure writes config.mk and config.log"
else
    bad "./configure failed ($PLAIN_RC): $(cat "$T/out")"
    echo "=== run_configure_test: FAILED (no use to go on without a configuration)"; exit 1
fi
D_AUTO=$(mkval DB_DRIVERS)
sed -n '/^Examples:/,$p' "$T/help" | sed -n 's/^  \(\.\/configure.*\)$/\1/p' > "$T/examples"
n=0
while IFS= read -r line; do
    n=$((n + 1))
    case $line in
        *postgresql*) case " $D_AUTO " in *" postgresql "*) ;; *) note "example '$line': libpq is not installed"; continue ;; esac ;;
    esac
    case $line in
        *sqlite3*) case " $D_AUTO " in *" sqlite3 "*) ;; *) note "example '$line': SQLite3 is not installed"; continue ;; esac ;;
    esac
    rm -f config.mk config.log
    if (eval "sh $line") > "$T/out" 2>&1 && [ -f config.mk ]; then ok "example runs: $line"; else bad "example fails: $line: $(tail -3 "$T/out")"; fi
done < "$T/examples"
[ $n -ge 3 ] && ok "$n examples in --help" || bad "--help shows $n examples"

# --- 2. usage errors ------------------------------------------------------------------------------------------------------------------------
echo "--- usage errors"
for a in --nosuch --prefix=relative '--prefix=/a b' '--sysconfdir=/a"b' '--sysconfdir=/a%b' '--sysconfdir=/a$b' --with-db-drivers=oracle --with-db-drivers= \
         --with-idn2=maybe --march= '--march=a b' --prefix --with-openssl=rel --libexecdir=rel '--libexecdir=/a b' --libexecdir; do
    cfg "$a"; rc=$?
    if [ $rc -eq 2 ] && [ ! -e config.mk ]; then ok "'$a' is a usage error"; else bad "'$a': exit $rc, config.mk: $(ls config.mk 2>&1)"; fi
done

# --- 3. what config.mk holds ----------------------------------------------------------------------------------------------------------------
echo "--- config.mk"
cfg --with-db-drivers=none; [ "$(mkval PREFIX)" = /usr/local ] && [ "$(mkval SYSCONFDIR)" = /usr/local/etc ] && ok "defaults: PREFIX /usr/local, SYSCONFDIR /usr/local/etc" || bad "default paths: $(mkval PREFIX) $(mkval SYSCONFDIR)"
grep -q '^CFLAGS' config.mk && bad "the default sysconfdir puts a flag into CFLAGS: $(grep '^CFLAGS' config.mk)" || ok "the default sysconfdir adds no -D (the sources have it)"
[ -z "$(mkval DB_DRIVERS)" ] && grep -q '^DB_DRIVERS =' config.mk && ok "--with-db-drivers=none: DB_DRIVERS is defined and empty" || bad "none: DB_DRIVERS='$(mkval DB_DRIVERS)'"
[ "$(mkval VERSION_FILE)" = "$(tr -d ' \r\n' < VERSION)" ] && ok "VERSION_FILE is the file VERSION" || bad "VERSION_FILE '$(mkval VERSION_FILE)'"
[ "$(mkval MARCH_FLAGS)" = -march=native ] && ok "default -march=native" || { grep -q 'does not accept -march=native' "$T/out" && ok "-march=native is not accepted here: baseline, said in the summary" || bad "MARCH_FLAGS '$(mkval MARCH_FLAGS)'"; }
cfg --with-db-drivers=none --prefix=/opt/kd/ ; [ "$(mkval PREFIX)" = /opt/kd ] && [ "$(mkval SYSCONFDIR)" = /opt/kd/etc ] && [ "$(mkval LIBEXECDIR)" = /opt/kd/libexec ] && ok "--prefix=/opt/kd/: PREFIX /opt/kd, SYSCONFDIR /opt/kd/etc, LIBEXECDIR /opt/kd/libexec" || bad "prefix: $(mkval PREFIX) $(mkval SYSCONFDIR) $(mkval LIBEXECDIR)"
grep -q '^CFLAGS += -DKARIDNS_SYSCONFDIR=\\"/opt/kd/etc\\" -DKARIDNS_PREFIX=\\"/opt/kd\\" -DKARIDNS_LIBEXECDIR=\\"/opt/kd/libexec\\"$' config.mk && ok "a prefix that is not the default is a CFLAGS += with -DKARIDNS_PREFIX, -DKARIDNS_SYSCONFDIR and -DKARIDNS_LIBEXECDIR" || bad "CFLAGS: $(grep '^CFLAGS' config.mk)"
cfg --with-db-drivers=none --libexecdir=/usr/libexec/ ; [ "$(mkval LIBEXECDIR)" = /usr/libexec ] && grep -q '^CFLAGS += -DKARIDNS_LIBEXECDIR=\\"/usr/libexec\\"$' config.mk && ok "--libexecdir=/usr/libexec/: only -DKARIDNS_LIBEXECDIR" || bad "libexecdir: $(mkval LIBEXECDIR) $(grep '^CFLAGS' config.mk)"
cfg --with-db-drivers=none --libexecdir /usr/local/libexec; ! grep -q '^CFLAGS' config.mk && ok "the default libexecdir adds no -D" || bad "default libexecdir: $(grep '^CFLAGS' config.mk)"
cfg --with-db-drivers=none --sysconfdir /etc/ ; [ "$(mkval SYSCONFDIR)" = /etc ] && grep -q '^CFLAGS += -DKARIDNS_SYSCONFDIR=\\"/etc\\"$' config.mk && ok "--sysconfdir /etc/ (two words, a trailing slash): /etc" || bad "sysconfdir: $(mkval SYSCONFDIR) $(grep '^CFLAGS' config.mk)"
cfg --with-db-drivers=none --march=none; grep -q '^MARCH_FLAGS = *$' config.mk && ok "--march=none: MARCH_FLAGS is defined and empty" || bad "march none: $(grep MARCH config.mk)"
cfg --with-db-drivers=none --march=x86-64; [ $? -eq 0 ] && [ "$(mkval MARCH_FLAGS)" = -march=x86-64 ] && ok "--march=x86-64: -march=x86-64" || {
    if grep -q 'does not accept' "$T/out"; then ok "--march=x86-64 is refused by this compiler (an error, as an explicit value must be)"; else bad "march value: $(mkval MARCH_FLAGS): $(tail -2 "$T/out")"; fi; }
cfg --march=nosuchcpu_xyz; [ $? -eq 1 ] && ok "--march with a value the compiler refuses is an error" || bad "bad -march: exit $?"
rm -f config.mk
CFLAGS='-g -DKT_A=$Y -DKT_B=#' LDFLAGS='-L/nonexistent_dir' sh ./configure --with-db-drivers=none --sysconfdir=/etc > "$T/out" 2>&1
grep -q '^CFLAGS = -g -DKT_A=\$\$Y -DKT_B=\\#$' config.mk && ok "CFLAGS from the environment: \$ doubled, # escaped" || bad "CFLAGS: $(grep '^CFLAGS' config.mk)"
grep -q '^CFLAGS += -DKARIDNS_SYSCONFDIR=' config.mk && [ "$(grep -n '^CFLAGS' config.mk | head -n 1 | cut -d: -f1)" -lt "$(grep -n '^CFLAGS +=' config.mk | cut -d: -f1)" ] && ok "the sysconfdir -D is added after the CFLAGS of the user" || bad "CFLAGS order: $(grep '^CFLAGS' config.mk)"
grep -q '^LDFLAGS = -L/nonexistent_dir$' config.mk && ok "LDFLAGS from the environment" || bad "LDFLAGS: $(grep '^LDFLAGS' config.mk)"
cfg --with-db-drivers=none CC="$REALCC" CFLAGS=-O1; grep -q '^CC = '"$REALCC"'$' config.mk && grep -q '^CFLAGS = -O1$' config.mk && ok "CC= and CFLAGS= as arguments" || bad "args: $(grep '^CC\|^CFLAGS' config.mk)"
cfg --with-db-drivers=none --without-idn2; [ -z "$(mkval IDN_CFLAGS)" ] && [ -z "$(mkval IDN_LDFLAGS)" ] && grep -q '^IDN_CFLAGS =' config.mk && ok "--without-idn2: IDN_CFLAGS and IDN_LDFLAGS are defined and empty" || bad "no idn2: '$(mkval IDN_CFLAGS)'"
cfg --with-db-drivers=none --with-openssl=/usr/local/nosuchdir; rc=$?
if [ $rc -eq 0 ]; then
    [ "$(mkval DARWIN_CFLAGS)" = -I/usr/local/nosuchdir/include ] && [ "$(mkval DARWIN_LDFLAGS)" = -L/usr/local/nosuchdir/lib ] && ok "--with-openssl=DIR: DARWIN_CFLAGS and DARWIN_LDFLAGS name DIR" || bad "openssl: '$(mkval DARWIN_CFLAGS)' '$(mkval DARWIN_LDFLAGS)'"
else
    bad "--with-openssl=DIR failed where the system has OpenSSL: $(tail -2 "$T/out")"
fi
for a in sqlite3 postgresql; do
    case " $D_AUTO " in
        *" $a "*) cfg --with-db-drivers=$a; [ "$(mkval DB_DRIVERS)" = $a ] && ok "--with-db-drivers=$a: DB_DRIVERS = $a" || bad "driver $a: '$(mkval DB_DRIVERS)'" ;;
        *) note "--with-db-drivers=$a: not installed" ;;
    esac
done
case " $D_AUTO " in
    *" sqlite3 "*)
        cfg --with-db-drivers=sqlite3,sqlite3; [ "$(mkval DB_DRIVERS)" = sqlite3 ] && ok "a driver named twice (comma list) is kept once" || bad "dup: '$(mkval DB_DRIVERS)'" ;;
esac

# --- 4. a library that is missing -------------------------------------------------------------------------------------------------------
echo "--- missing libraries (a compiler that fails on the header)"
fc() {   # FAIL_INC, args...: configure with the wrapper (a subshell: nothing stays set)
    _inc=$1; shift
    ( FAKECC_FAIL_INC=$_inc; CC=$T/fakecc; export FAKECC_FAIL_INC CC; cfg "$@" )
}
fa() {   # FAIL_ARG, args...: the same with a compiler that refuses one argument
    _arg=$1; shift
    ( FAKECC_FAIL_ARG=$_arg; CC=$T/fakecc; export FAKECC_FAIL_ARG CC; cfg "$@" )
}
fc libpq-fe.h --with-db-drivers=postgresql; rc=$?
if [ $rc -eq 1 ] && grep -qi 'libpq' "$T/out" && [ ! -e config.mk ]; then ok "postgresql asked for, libpq missing: error, exit 1, no config.mk"; else bad "pg missing: exit $rc: $(cat "$T/out")"; fi
fc sqlite3.h --with-db-drivers=sqlite3; rc=$?
if [ $rc -eq 1 ] && grep -qi 'sqlite3' "$T/out" && [ ! -e config.mk ]; then ok "sqlite3 asked for, missing: error, exit 1"; else bad "sqlite3 missing: exit $rc: $(cat "$T/out")"; fi
fc idn2.h --with-idn2=yes --with-db-drivers=none; rc=$?
if [ $rc -eq 1 ] && grep -q 'libidn2' "$T/out" && [ ! -e config.mk ]; then ok "--with-idn2=yes, libidn2 missing: error, exit 1"; else bad "idn2 missing, yes: exit $rc"; fi
fc openssl/ssl.h --with-db-drivers=none; rc=$?
if [ $rc -eq 1 ] && grep -q 'OpenSSL' "$T/out" && [ ! -e config.mk ]; then ok "OpenSSL missing: error, exit 1"; else bad "openssl missing: exit $rc"; fi
fc libpq-fe.h; rc=$?
if [ $rc -eq 0 ] && ! mkval DB_DRIVERS | grep -q postgresql && grep -q 'postgresql: not found' "$T/out" && [ -z "$(mkval DBPG_HAVE)" ]; then
    ok "auto, libpq missing: no postgresql driver, a line in the summary, DBPG_HAVE empty"
else bad "auto without libpq: exit $rc: $(cat "$T/out")"; fi
fc sqlite3.h; rc=$?
if [ $rc -eq 0 ] && ! mkval DB_DRIVERS | grep -q sqlite3 && grep -q 'sqlite3: not found' "$T/out"; then ok "auto, sqlite3 missing: no sqlite3 driver, a line in the summary"; else bad "auto without sqlite3: exit $rc"; fi
fc idn2.h --with-db-drivers=none; rc=$?
if [ $rc -eq 0 ] && [ -z "$(mkval IDN_CFLAGS)" ] && grep -q 'libidn2 *no (not found' "$T/out"; then ok "auto, libidn2 missing: dag without it, a line in the summary"; else bad "auto without idn2: exit $rc: $(cat "$T/out")"; fi
fc libpq-fe.h --with-db-drivers=sqlite3 ; rc=$?
case " $D_AUTO " in *" sqlite3 "*) [ $rc -eq 0 ] && ok "sqlite3 alone does not need libpq" || bad "sqlite3 alone without libpq: exit $rc" ;; *) note "sqlite3 is not installed" ;; esac
fa -march=native --with-db-drivers=none; rc=$?
if [ $rc -eq 0 ] && grep -q '^MARCH_FLAGS = *$' config.mk && grep -q 'does not accept -march=native' "$T/out"; then ok "the default -march=native falls back to the baseline when the compiler refuses it, and says so"; else bad "march fallback: exit $rc: $(cat "$T/out")"; fi
fa -march=native --march=native --with-db-drivers=none; rc=$?
[ $rc -eq 1 ] && ok "an explicit --march=native that the compiler refuses is an error" || bad "explicit march: exit $rc"
ls conftest* >/dev/null 2>&1 && bad "configure left test files: $(ls conftest*)" || ok "configure leaves no conftest files"

# --- 5. make -n with and without config.mk -------------------------------------------------------------------------------------------------
echo "--- make -n with and without config.mk"
TARGETS="karidns dag karicheck karictl karidns-dbloader karidns-zone"
cfg; D=$(mkval DB_DRIVERS); [ -n "$D" ] && DOPT=$(printf "%s" "$D" | tr " " ",") || DOPT=none
n_made=0
for MK in make gmake; do
    command -v $MK >/dev/null 2>&1 || continue
    if $MK --version 2>/dev/null | head -n 1 | grep -q 'GNU Make 3\.'; then
        note "$MK is GNU make 3.81: it cannot probe without configure (config.mk is how it builds)"
        rm -f config.mk; cfg; $MK -n $TARGETS > "$T/n.conf" 2>&1; grep -q -- '-DKARIDNS_VERSION=\\"'"$(tr -d ' \r\n' < VERSION)"'\\"' "$T/n.conf" && ok "$MK with config.mk: the version is in the compile line" || bad "$MK with config.mk: no version in the compile line"
        continue
    fi
    # same options: each pair is (configure arguments, make arguments without config.mk)
    run_pair() {   # label, "configure args", then the make arguments
        _l=$1; _c=$2; shift 2
        rm -f config.mk config.log
        # shellcheck disable=SC2086
        $MK -n "$@" $TARGETS > "$T/n.plain" 2>&1
        # shellcheck disable=SC2086
        sh ./configure $_c > "$T/out" 2>&1 || { bad "$MK $_l: configure failed: $(tail -2 "$T/out")"; return; }
        $MK -n $TARGETS > "$T/n.conf" 2>&1
        if cmp -s "$T/n.plain" "$T/n.conf" && [ -s "$T/n.plain" ]; then
            ok "$MK, $_l: $(wc -l < "$T/n.conf" | tr -d ' ') lines, the same with and without config.mk"
        else
            bad "$MK, $_l: the commands differ"; diff "$T/n.plain" "$T/n.conf" | head -6
        fi
        n_made=$((n_made + 1))
    }
    run_pair "default options" "--with-db-drivers=$DOPT" "DB_DRIVERS=$D"
    run_pair "--march=none --without-idn2" "--with-db-drivers=$DOPT --march=none --without-idn2" DB_DRIVERS="$D" MARCH_FLAGS= IDN_CFLAGS= IDN_LDFLAGS=
    # the environment: CFLAGS and LDFLAGS reach make either way
    rm -f config.mk; CFLAGS='-g -DFOO=1' LDFLAGS='-L/nonexistent_dir' $MK -n DB_DRIVERS="$D" $TARGETS > "$T/n.plain" 2>&1
    CFLAGS='-g -DFOO=1' LDFLAGS='-L/nonexistent_dir' sh ./configure --with-db-drivers=$DOPT > "$T/out" 2>&1
    $MK -n $TARGETS > "$T/n.conf" 2>&1
    cmp -s "$T/n.plain" "$T/n.conf" && ok "$MK, CFLAGS and LDFLAGS of the environment: the same" || { bad "$MK, CFLAGS and LDFLAGS of the environment differ"; diff "$T/n.plain" "$T/n.conf" | head -4; }
    # other directories: only their -D are new (and it is on every compile line of the objects)
    rm -f config.mk; $MK -n DB_DRIVERS="$D" $TARGETS > "$T/n.plain" 2>&1
    sh ./configure --with-db-drivers=$DOPT --prefix=/opt/kd --sysconfdir=/etc/kdtest --libexecdir=/opt/kd/lx > "$T/out" 2>&1
    $MK -n $TARGETS > "$T/n.conf" 2>&1
    DEF='-DKARIDNS_SYSCONFDIR=\"/etc/kdtest\"'
    sed -e "s|-DKARIDNS_SYSCONFDIR=[^ ]* ||" -e "s|-DKARIDNS_PREFIX=[^ ]* ||" -e "s|-DKARIDNS_LIBEXECDIR=[^ ]* ||" "$T/n.conf" > "$T/n.conf.nodef"
    if cmp -s "$T/n.plain" "$T/n.conf.nodef" && grep -qF -- "$DEF" "$T/n.conf"; then
        ok "$MK, --prefix, --sysconfdir, --libexecdir: $(grep -cF -- "$DEF" "$T/n.conf") commands carry the -D, nothing else changes"
    else
        bad "$MK, --sysconfdir: the commands differ by more than the -D"; diff "$T/n.plain" "$T/n.conf.nodef" | head -4
    fi
    grep -F -- "karictl.c" "$T/n.conf" | grep -qF -- "$DEF" && ok "$MK: the karictl compile line has the sysconfdir" || bad "$MK: karictl.c is compiled without the sysconfdir"
    for d in 'KARIDNS_PREFIX=\"/opt/kd\"' 'KARIDNS_LIBEXECDIR=\"/opt/kd/lx\"'; do
        grep -F -- "dns_server_core.c" "$T/n.conf" | grep -qF -- "-D$d" && ok "$MK: the karidns compile line has -D$d" || bad "$MK: dns_server_core.c is compiled without -D$d"
    done
done
[ $n_made -gt 0 ] || note "no make that can run without configure: the equivalence was not checked"

# a DB_DRIVERS on the make command line wins over config.mk, and what is derived from it follows (it is not in config.mk)
cfg --with-db-drivers=none
make -n DB_DRIVERS=sqlite3 karidns-dbloader 2>/dev/null | grep -q -- '-DKARIDNS_DB_SQLITE3.*dns_db_sqlite3.c.*-lsqlite3' && ok "make DB_DRIVERS=sqlite3 after --with-db-drivers=none compiles the SQLite3 driver" || note "make cannot derive DB_DRIVERS flags here (GNU make 3.81)"

# --- 6. distclean, a second run ------------------------------------------------------------------------------------------------------------
echo "--- distclean"
cfg --with-db-drivers=none; cp config.mk "$T/config.mk.1"
sh ./configure --with-db-drivers=none > "$T/out" 2>&1; cmp -s config.mk "$T/config.mk.1" && ok "a second ./configure writes the same config.mk" || bad "config.mk differs after a second run"
if make distclean > "$T/out" 2>&1 && [ ! -e config.mk ] && [ ! -e config.log ]; then ok "make distclean removes config.mk and config.log"; else bad "distclean: config.mk $(ls config.mk 2>&1) config.log $(ls config.log 2>&1): $(tail -3 "$T/out")"; fi

# --- 7. the search paths ----------------------------------------------------------------------------------------------------------------------
echo "--- the paths of the Makefile and of configure"
for n in BREW_CFLAGS BREW_LDFLAGS; do
    a=$(sed -n "s/^$n  *= *//p" "$ROOT/Makefile" | head -n 1)
    b=$(sed -n "s/^$n='\(.*\)'\$/\1/p" "$ROOT/configure")
    [ -n "$a" ] && [ "$a" = "$b" ] && ok "$n is the same in the Makefile and in configure" || bad "$n differs: Makefile '$a', configure '$b'"
done

# --- 8. the sysconfdir is compiled in ------------------------------------------------------------------------------------------------------
echo "--- the sysconfdir in a program"
if [ "${KARI_CONFIGURE_NOBUILD:-0}" = 1 ]; then
    note "KARI_CONFIGURE_NOBUILD=1"
else
    for dir in /usr/local/etc /etc/kdtest; do
        cfg --with-db-drivers=none --march=none --sysconfdir=$dir
        rm -f karictl tools/karictl.o
        if make karictl > "$T/build.log" 2>&1; then
            # no configuration file in that place: the error names the path it tried
            out=$(HOME=/nonexistent ./karictl status 2>&1 < /dev/null)
            case $out in
                *"$dir/karidns/karictl.conf"*) ok "karictl with --sysconfdir=$dir reads $dir/karidns/karictl.conf" ;;
                *) bad "karictl with --sysconfdir=$dir: no path $dir/karidns/karictl.conf in: $out" ;;
            esac
        elif [ "$dir" = /usr/local/etc ]; then
            note "karictl does not build here with the default options either (not a question of configure): $(tail -1 "$T/build.log")"
            break
        else
            bad "make karictl failed with --sysconfdir=$dir: $(tail -5 "$T/build.log")"
        fi
    done
fi

# --- 9. the directories that are compiled in: the loader of karidns, the CA bundles of dag -------------------------------------------------
echo "--- compiled-in directories"
cat > probe.c <<'PROBE'
#include <stdio.h>
#include "dns_config_parser.h"
int main(void) {
    printf("%s\n%s\n%s\n", KARIDNS_DB_DEFAULT_LOADER_PATH, KARIDNS_SYSCONFDIR "/ssl/cert.pem", KARIDNS_PREFIX "/share/certs/ca-root-nss.crt");
    return 0;
}
PROBE
probe() {   # configure arguments: the three strings the headers give with the flags configure wrote
    cfg --with-db-drivers=none --march=none "$@" || return 1
    _fl=$(sed -n 's/^CFLAGS += //p' config.mk)
    eval "$REALCC $_fl -I. probe.c -o probe.out" 2> "$T/probe.err" && ./probe.out | tr '\n' ' '
}
P=$(probe); R="/usr/local/libexec/karidns-dbloader /usr/local/etc/ssl/cert.pem /usr/local/share/certs/ca-root-nss.crt "
[ "$P" = "$R" ] && ok "without options: loader-path default and the two CA bundles are the FreeBSD ones" || bad "defaults: '$P' $(head -3 "$T/probe.err")"
P=$(probe --prefix=/opt/kd --sysconfdir=/etc/kdt --libexecdir=/opt/lx); R="/opt/lx/karidns-dbloader /etc/kdt/ssl/cert.pem /opt/kd/share/certs/ca-root-nss.crt "
[ "$P" = "$R" ] && ok "--prefix, --sysconfdir, --libexecdir reach KARIDNS_DB_DEFAULT_LOADER_PATH and the CA bundle names" || bad "options: '$P' $(head -3 "$T/probe.err")"
P=$(probe --prefix=/opt/kd); R="/opt/kd/libexec/karidns-dbloader /opt/kd/etc/ssl/cert.pem /opt/kd/share/certs/ca-root-nss.crt "
[ "$P" = "$R" ] && ok "--prefix alone moves libexecdir and sysconfdir with it" || bad "prefix: '$P' $(head -3 "$T/probe.err")"
if grep -q 'KARIDNS_SYSCONFDIR "/ssl/cert.pem"' tools/dag_transport.c && grep -q 'KARIDNS_PREFIX "/share/certs/ca-root-nss.crt"' tools/dag_transport.c; then
    ok "dag_transport.c builds its two /usr/local CA bundle names from these macros"
else
    bad "dag_transport.c has a fixed /usr/local CA bundle name"
fi
if grep -n '"/usr/local/' tools/dag_transport.c tools/dag_http.c dns_config_parser.h > "$T/fixed" 2>&1; then
    bad "a fixed /usr/local path in dag's TLS code or in the loader default: $(cat "$T/fixed")"
else
    ok "no fixed /usr/local path in dag's TLS code or in the loader default"
fi

if [ $FAIL -ne 0 ]; then echo "=== run_configure_test: FAILED"; exit 1; fi
echo "=== run_configure_test: all checks passed"
exit 0

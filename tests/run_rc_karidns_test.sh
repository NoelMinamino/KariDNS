#!/bin/sh
# run_rc_karidns_test.sh - the log directory of packaging/freebsd/rc.d/karidns (0.7, K-6; docs/distribution.md "The user karidns").
#
# The rc script never changes an existing log directory (karidns_log_dir, /var/log/named).  It creates a missing one for karidns_log_owner of
# rc.conf ("user" or "user:group"), else for options { user } (and { group }, else the user's primary group) of the configuration, which it
# reads with the tokens of the server's lexer (karidns_conf_identity); when neither tells, or the user does not exist, it refuses to start.
# The script is run with a stub of rc.subr, of id(1) and install(1) (the users of each case are made up, install only records) and of
# karicheck / karictl (the paths /usr/local/bin/... are replaced), so that nothing of the host is used or changed and no user has to exist:
#   1. karidns_conf_identity: the sample (karidns:karidns), a block, a one-line options, comments of the three kinds (also a `user` in a
#      block comment), quoted and bare values, user"x"; (one word for the server too: no user), the last user wins, user in a nested block
#      or another statement is not taken, include one level deep (absolute, relative to the file, relative to options { directory }), and
#      the failures: an include in an included file, a missing include, an unclosed comment or string, unbalanced braces;
#   2. prestart: karicheck first, /var/run/karidns root:wheel 0755; an existing log directory (another owner) is left alone, also with a
#      configuration that names nobody; a missing one is made for the configuration's user and group, for karidns_log_owner (user, user:group);
#      a missing one with no user to tell, or a user that does not exist: the start is refused with a message and nothing is made.
# The sample configuration names user and group karidns, and the package creates them (MANIFEST.in).  Needs sh, sed, awk.  Run as root or not:
# everything it writes is in its own temporary directory.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -10 | sed 's/^/         /'; }
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_rc.XXXXXX") || exit 1
trap 'rm -rf "$T"' EXIT
trap 'exit 130' INT TERM

# the rc script with a stub rc.subr: run_rc_command runs its argument (a function and, for the test, its arguments)
cat > "$T/rc.subr" <<'EOF'
load_rc_config() { :; }
run_rc_command() { eval "$1"; }
# id -u USER / id -gn USER for the users of FAKE_USERS only (the primary group of USER is "USER-g")
id() {
    case "$1" in
        -u|-gn) for u in $FAKE_USERS; do [ "$u" = "$2" ] && { [ "$1" = -u ] && echo 1000 || echo "$2-g"; return 0; }; done; return 1 ;;
    esac
    command id "$@"
}
install() { echo "install $*" >> "$RC_LOG"; }
EOF
mkdir "$T/bin"
printf '#!/bin/sh\necho "karicheck $*" >> "$RC_LOG"\nexit "${KARICHECK_EXIT:-0}"\n' > "$T/bin/karicheck"
printf '#!/bin/sh\necho "karictl $*" >> "$RC_LOG"\n' > "$T/bin/karictl"
chmod 755 "$T/bin/karicheck" "$T/bin/karictl"
sed -e "s|^\. /etc/rc.subr$|. $T/rc.subr|" -e "s|/usr/local/bin/karicheck|$T/bin/karicheck|g" -e "s|/usr/local/bin/karictl|$T/bin/karictl|g" \
    "$ROOT/packaging/freebsd/rc.d/karidns" > "$T/karidns"
grep -q "^\. $T/rc.subr$" "$T/karidns" || { echo "  [FAIL] the rc script does not source /etc/rc.subr"; exit 1; }
grep -q '/usr/local/bin/kari' "$T/karidns" && { echo "  [FAIL] the rc script still names a program of the host"; exit 1; }
same() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', wanted '$3')"; fi; }
# ident CONFIG: what karidns_conf_identity says, or FAIL
ident() { FAKE_USERS="" karidns_config=$1 RC_LOG=$T/log sh "$T/karidns" "karidns_conf_identity '$1'" 2>/dev/null || echo FAIL; }
c() { printf "$2" > "$T/$1"; }

echo "-- karidns_conf_identity: the user and group of options as karidns reads them"
grep -q '^    user "karidns";' "$ROOT/karidns.conf.sample" && grep -q '^    group "karidns";' "$ROOT/karidns.conf.sample" && ok "karidns.conf.sample names user and group karidns" || bad "the sample does not name karidns"
grep -q 'pw useradd karidns -g karidns' "$ROOT/packaging/freebsd/MANIFEST.in" && ok "the server package creates the user karidns (MANIFEST.in)" || bad "MANIFEST.in creates no user karidns"
grep -q 'log/named' "$ROOT/packaging/freebsd/MANIFEST.in" && ! sed -n '/post-install/,/^EOD/p' "$ROOT/packaging/freebsd/MANIFEST.in" | grep -q 'log/named' && ok "the package does not make /var/log/named (the rc script does, for the user of the configuration)" || bad "MANIFEST.in: post-install and /var/log/named"
same "the sample: karidns:karidns" "$(ident "$ROOT/karidns.conf.sample")" karidns:karidns
c block.conf 'options {\n    port 53;\n    user "bind";\n    group "bind";\n};\n'
same "a block: bind:bind" "$(ident "$T/block.conf")" bind:bind
c oneline.conf 'options { port 53; user "karidns"; group "wheel2"; };\n'
same "a one-line options" "$(ident "$T/oneline.conf")" karidns:wheel2
c bare.conf 'options{user karidns;};zone "x"{type master;file "x";};\n'
same "bare values, no spaces around the braces" "$(ident "$T/bare.conf")" karidns:
c nospace.conf 'options {\n    user"karidns";\n};\n'
same 'user"karidns"; is one word (the server refuses it): no user' "$(ident "$T/nospace.conf")" :
c comments.conf 'options {\n    // user "bind";\n    # user "named";\n    /* user "toor";\n       group "x"; */ user /* c */ "karidns"; // user "y";\n};\n'
same "line comments and a block comment are not read (one inside a statement)" "$(ident "$T/comments.conf")" karidns:
c last.conf 'options { user "a"; };\noptions { user "b"; group "g"; };\n'
same "the last user and group win" "$(ident "$T/last.conf")" b:g
c nested.conf 'logging { user "x"; };\noptions {\n    database { loader-user "loader"; user "y"; };\n    port 53;\n};\nzone "user" { type master; file "user"; };\n'
same "a user in another statement or in a nested block is not taken" "$(ident "$T/nested.conf")" :
c string.conf 'options { pid-file "/var/run/a#b//c"; user "karidns"; };\n'
same "# and // inside a quoted string are text" "$(ident "$T/string.conf")" karidns:
mkdir "$T/inc" "$T/dir"
c inc/opts.conf 'options {\n    user "karidns";\n    group "karidns";\n};\n'
c inc/abs.conf "include \"$T/inc/opts.conf\";\n"
same "include with an absolute path" "$(ident "$T/inc/abs.conf")" karidns:karidns
c inc/rel.conf 'include "opts.conf";\n'
same "include relative to the directory of the file" "$(ident "$T/inc/rel.conf")" karidns:karidns
c inc/body.conf '    user "inside";\n'
c inc/inopt.conf 'options {\n    port 53;\n    include "body.conf";\n};\n'
same "include inside the options block" "$(ident "$T/inc/inopt.conf")" inside:
c dir/opts.conf 'options { user "fromdir"; };\n'
c inc/dir.conf "options { directory \"$T/dir\"; };\ninclude \"opts.conf\";\n"
same "a relative include after options { directory } is read from it" "$(ident "$T/inc/dir.conf")" fromdir:
c inc/deep2.conf 'include "opts.conf";\n'
c inc/deep.conf 'include "deep2.conf";\n'
same "an include in an included file: cannot tell" "$(ident "$T/inc/deep.conf")" FAIL
c inc/missing.conf 'include "nosuchfile.conf";\n'
same "a missing include: cannot tell" "$(ident "$T/inc/missing.conf")" FAIL
c inc/reldir.conf 'options { directory "data"; };\ninclude "opts.conf";\n'
same "a relative include after a relative directory: cannot tell" "$(ident "$T/inc/reldir.conf")" FAIL
c unclosed.conf 'options { user "karidns"; };\n/* never closed\n'
same "an unclosed comment: cannot tell" "$(ident "$T/unclosed.conf")" FAIL
c unclosed2.conf 'options { user "karidns;\n};\n'
same "an unclosed string: cannot tell" "$(ident "$T/unclosed2.conf")" FAIL
c braces.conf 'options { user "karidns";\n'
same "unbalanced braces: cannot tell" "$(ident "$T/braces.conf")" FAIL
same "a configuration file that is missing: cannot tell" "$(ident "$T/none.conf")" FAIL
c nouser.conf 'options {\n    port 10053;\n};\n'
same "no user: empty" "$(ident "$T/nouser.conf")" :

echo "-- prestart"
# pre USERS CONFIG LOGDIR [LOG_OWNER]: run karidns_prestart, its output in $T/pre.out, what it ran in $T/log
pre() { : > "$T/log"; FAKE_USERS=$1 karidns_config=$2 karidns_log_dir=$3 karidns_log_owner=${4:-} RC_LOG=$T/log sh "$T/karidns" karidns_prestart > "$T/pre.out" 2>&1; }
mkdir "$T/existing"
if pre "root bind karidns" "$ROOT/karidns.conf.sample" "$T/existing"; then ok "prestart runs"; else bad "prestart failed" "$(cat "$T/pre.out")"; fi
head -1 "$T/log" | grep -qx "karicheck conf $ROOT/karidns.conf.sample" && ok "karicheck conf runs first (the stub, not a karicheck of the host)" || bad "karicheck" "$(cat "$T/log")"
grep -qx 'install -d -o root -g wheel -m 0755 /var/run/karidns' "$T/log" && ok "/var/run/karidns: root:wheel 0755" || bad "/var/run/karidns" "$(cat "$T/log")"
grep -q "$T/existing" "$T/log" && bad "an existing log directory was changed" "$(cat "$T/log")" || ok "an existing log directory (another owner) is left alone"
pre "root" "$T/nouser.conf" "$T/existing" && ! grep -q "$T/existing" "$T/log" && ok "...also when the configuration names no user and no user exists" || bad "existing directory, no user" "$(cat "$T/pre.out" "$T/log")"
pre "root" "$T/inc/deep.conf" "$T/existing" "" && ok "...and when the configuration cannot be read by the script" || bad "existing directory, deep include" "$(cat "$T/pre.out")"
pre "root bind karidns" "$ROOT/karidns.conf.sample" "$T/new"
grep -qx "install -d -o karidns -g karidns -m 0755 $T/new" "$T/log" && ok "a missing log directory: karidns:karidns (user and group of the sample)" || bad "missing directory, sample" "$(cat "$T/log" "$T/pre.out")"
pre "root bind karidns" "$T/block.conf" "$T/new"
grep -qx "install -d -o bind -g bind -m 0755 $T/new" "$T/log" && ok "...bind:bind for a configuration that names bind (an earlier version's)" || bad "missing directory, bind" "$(cat "$T/log")"
pre "root karidns" "$T/inc/rel.conf" "$T/new"
grep -qx "install -d -o karidns -g karidns -m 0755 $T/new" "$T/log" && ok "...the user of an included options block" || bad "missing directory, include" "$(cat "$T/log" "$T/pre.out")"
pre "root karidns" "$T/bare.conf" "$T/new"
grep -qx "install -d -o karidns -g karidns-g -m 0755 $T/new" "$T/log" && ok "...no group: the user's primary group" || bad "missing directory, primary group" "$(cat "$T/log")"
pre "root bind karidns" "$T/block.conf" "$T/new" karidns
grep -qx "install -d -o karidns -g karidns-g -m 0755 $T/new" "$T/log" && ok "karidns_log_owner=user wins, with its primary group" || bad "karidns_log_owner=user" "$(cat "$T/log")"
pre "root bind karidns" "$T/nouser.conf" "$T/new" karidns:wheel
grep -qx "install -d -o karidns -g wheel -m 0755 $T/new" "$T/log" && ok "karidns_log_owner=user:group" || bad "karidns_log_owner=user:group" "$(cat "$T/log")"
for cf in nouser.conf inc/deep.conf nospace.conf; do
    if pre "root bind named karidns" "$T/$cf" "$T/new"; then bad "$cf: prestart starts with a missing log directory and no user"; else
        grep -q 'karidns_log_owner' "$T/pre.out" && ok "$cf, missing directory: the start is refused, with what to do (no fallback to bind)" || bad "$cf: message" "$(cat "$T/pre.out")"
    fi
    grep -q "$T/new" "$T/log" && bad "...but $cf made the directory"
done
if pre "root bind" "$T/inc/abs.conf" "$T/new"; then bad "prestart starts for a user that does not exist"; else grep -q "user 'karidns' of options { user }.*does not exist" "$T/pre.out" && ok "a user that does not exist: refused, and said" || bad "missing user: message" "$(cat "$T/pre.out")"; fi
if pre "root" "$T/nouser.conf" "$T/new" nosuch:wheel; then bad "prestart starts for a karidns_log_owner that does not exist"; else grep -q "user 'nosuch' of karidns_log_owner does not exist" "$T/pre.out" && ok "a karidns_log_owner that does not exist: refused" || bad "karidns_log_owner missing: message" "$(cat "$T/pre.out")"; fi
grep -q "$T/new" "$T/log" && bad "...but it made the directory" || ok "...and nothing is made"
: > "$T/log"
FAKE_USERS="root karidns" karidns_config=$ROOT/karidns.conf.sample karidns_log_dir=$T/new KARICHECK_EXIT=1 RC_LOG=$T/log sh "$T/karidns" karidns_prestart > "$T/pre.out" 2>&1 && bad "prestart starts when karicheck fails" || { grep -q install "$T/log" && bad "a failed karicheck still made directories" || ok "a failed karicheck stops the start before any directory"; }

echo
echo "=== run_rc_karidns_test: $FAILS failed, $PASS passed ==="
[ "$FAILS" = 0 ]

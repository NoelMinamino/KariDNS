#!/bin/sh
# run_rc_karidns_test.sh - the run user of packaging/freebsd/rc.d/karidns (0.7, K-6; docs/distribution.md "The user karidns").
#
# The rc script gives /var/log/named to the user the server runs as (karidns_run_user): karidns_log_owner of rc.conf, else the `user` of the
# configuration when that user exists, else bind, named or karidns, the first that exists.  The script is run with a stub of rc.subr and of id(1)
# (the users of each case are made up), so that nothing of the host is used or changed and no user has to exist:
#   1. a fresh installation: the sample configuration of the package (user "karidns") with bind and karidns on the system -> karidns;
#   2. an upgrade: a configuration of an earlier version with user "bind" (or "named") -> bind (named), also when karidns exists;
#   3. a configuration without `user`: bind, else named, else karidns (bind and named as before 0.7);
#   4. a `user` that does not exist, a commented-out `user`: the order of 3;
#   5. karidns_log_owner wins; no candidate at all: the function fails and prestart refuses to start;
#   6. prestart: karicheck first, then /var/run/karidns root:wheel 0755 and /var/log/named to that user and its group (install(1) recorded).
# The sample configuration names user and group karidns, and the package creates them (build_pkg.sh / MANIFEST.in).  Needs sh, sed, awk.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -10 | sed 's/^/         /'; }
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_rc.XXXXXX") || exit 1
trap 'rm -rf "$T"' EXIT
trap 'exit 130' INT TERM

# the rc script with a stub rc.subr: run_rc_command runs the function named by its argument
cat > "$T/rc.subr" <<'EOF'
load_rc_config() { :; }
run_rc_command() { "$1"; }
# id -u USER / id -gn USER for the users of FAKE_USERS only
id() {
    case "$1" in
        -u|-gn) for u in $FAKE_USERS; do [ "$u" = "$2" ] && { [ "$1" = -u ] && echo 1000 || echo "$2"; return 0; }; done; return 1 ;;
    esac
    command id "$@"
}
install() { echo "install $*" >> "$RC_LOG"; }
EOF
sed -e "s|^\. /etc/rc.subr$|. $T/rc.subr|" "$ROOT/packaging/freebsd/rc.d/karidns" > "$T/karidns"
grep -q "^\. $T/rc.subr$" "$T/karidns" || { echo "  [FAIL] the rc script does not source /etc/rc.subr"; exit 1; }
# owner USERS CONFIG [LOG_OWNER]: what karidns_run_user says
owner() { FAKE_USERS=$1 karidns_config=$2 karidns_log_owner=${3:-} RC_LOG=$T/log sh "$T/karidns" karidns_run_user 2>/dev/null; }
same() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', wanted '$3')"; fi; }

printf 'options {\n    port 53;\n    user "bind";\n    group "bind";\n};\n' > "$T/bind.conf"
printf 'options {\n    user "named";\n    group "named";\n};\n' > "$T/named.conf"
printf 'options {\n    port 10053;\n};\n' > "$T/nouser.conf"
printf 'options {\n    user "nosuchuser";\n};\n' > "$T/missing.conf"
printf 'options {\n    // user "bind";\n    # user "named";\n    port 53;\n};\n' > "$T/commented.conf"

echo "-- the sample configuration of the package"
grep -q '^    user "karidns";' "$ROOT/karidns.conf.sample" && grep -q '^    group "karidns";' "$ROOT/karidns.conf.sample" && ok "karidns.conf.sample names user and group karidns" || bad "the sample does not name karidns"
grep -q 'pw useradd karidns -g karidns' "$ROOT/packaging/freebsd/MANIFEST.in" && ok "the server package creates the user karidns (MANIFEST.in)" || bad "MANIFEST.in creates no user karidns"
same "a fresh installation (sample, users bind and karidns): karidns" "$(owner "root bind karidns" "$ROOT/karidns.conf.sample")" karidns

echo "-- an upgrade keeps the user of the configuration"
same "user \"bind\" with karidns present: bind" "$(owner "root bind karidns" "$T/bind.conf")" bind
same "user \"named\" with bind and karidns present: named" "$(owner "root bind named karidns" "$T/named.conf")" named

echo "-- no user in the configuration: bind, named, karidns"
same "bind first" "$(owner "root bind named karidns" "$T/nouser.conf")" bind
same "named without bind" "$(owner "root named karidns" "$T/nouser.conf")" named
same "karidns without bind and named" "$(owner "root karidns" "$T/nouser.conf")" karidns
same "a user that does not exist: the same order" "$(owner "root named karidns" "$T/missing.conf")" named
same "a commented-out user is not read" "$(owner "root karidns" "$T/commented.conf")" karidns
same "a missing configuration file: the same order" "$(owner "root bind" "$T/none.conf")" bind

echo "-- karidns_log_owner, and no user at all"
same "karidns_log_owner wins" "$(owner "root bind karidns" "$ROOT/karidns.conf.sample" nobody)" nobody
if FAKE_USERS="root" karidns_config=$T/nouser.conf RC_LOG=$T/log sh "$T/karidns" karidns_run_user > /dev/null 2>&1; then bad "karidns_run_user succeeds without any candidate"; else ok "no candidate: karidns_run_user fails"; fi

echo "-- prestart"
: > "$T/log"
if FAKE_USERS="root bind karidns" karidns_config=$ROOT/karidns.conf.sample RC_LOG=$T/log sh "$T/karidns" karidns_prestart > "$T/pre.out" 2>&1; then ok "prestart runs"; else bad "prestart failed" "$(cat "$T/pre.out")"; fi
grep -qx 'install -d -o root -g wheel -m 0755 /var/run/karidns' "$T/log" && ok "/var/run/karidns: root:wheel 0755" || bad "/var/run/karidns" "$(cat "$T/log")"
grep -qx 'install -d -o karidns -g karidns -m 0755 /var/log/named' "$T/log" && ok "/var/log/named: karidns:karidns (the user of the sample)" || bad "/var/log/named" "$(cat "$T/log")"
: > "$T/log"
FAKE_USERS="root bind karidns" karidns_config=$T/bind.conf RC_LOG=$T/log sh "$T/karidns" karidns_prestart > /dev/null 2>&1
grep -qx 'install -d -o bind -g bind -m 0755 /var/log/named' "$T/log" && ok "/var/log/named: bind:bind for a configuration that names bind" || bad "/var/log/named for bind" "$(cat "$T/log")"
: > "$T/log"
if FAKE_USERS="root" karidns_config=$T/nouser.conf RC_LOG=$T/log sh "$T/karidns" karidns_prestart > "$T/pre.out" 2>&1; then bad "prestart starts without any user"; else grep -q 'none of the users' "$T/pre.out" && ok "prestart refuses to start without any user, and says why" || bad "prestart without a user: message" "$(cat "$T/pre.out")"; fi
grep -q '/var/log/named' "$T/log" && bad "...but made /var/log/named" || ok "...and makes no directory"

echo
echo "=== run_rc_karidns_test: $FAILS failed, $PASS passed ==="
[ "$FAILS" = 0 ]

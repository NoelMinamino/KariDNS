#!/bin/sh
# run_rc_service_dirs_test.sh - the directories the rc scripts of karidns-signer and karidns-webadmin make (0.7; packaging/freebsd/rc.d/karidns_signer
# karidns_signer_dirs, rc.d/karidns_webadmin karidns_webadmin_dirs; docs/karidns-signer.md, docs/karidns-webadmin.md).
#
# Neither script ever changes the owner or mode of a directory that exists, makes a missing directory only in an existing parent (the signer also
# /var/db/karidns-signer, the parent of its default work-dir), refuses a relative path, a . or .. component and a symbolic link in the path, and
# makes nothing for configtest.  The signer refuses an existing work-dir that karidns-signer --check would refuse (not the user's, or open to group
# or others: workdir.js checkWorkDir).  The scripts run with a stub of rc.subr, id(1), install(1) (recorded, so nothing is made), su(1), mount(8)
# and the program (karidns_*_wrapper); /var/db and /var/run in the scripts are replaced by directories of the test, so nothing of the host is used or changed:
#   signer: the default work-dir on a fresh installation (parent and work directory made), configtest on it (nothing made, the note, --check run),
#   an existing work-dir of the user (left as it is), one of another user or with mode 0755 (refused, left as it is, also by configtest), work-dir
#   in /var/tmp (only the work directory is made, never /var/tmp), a missing parent, a relative path, a .. component, a symbolic link in the path,
#   a file in the place of the work directory, the tmpfs mounted on the work directory;
#   webadmin: the default directory of the TOTP key (made at start, not by configtest), an existing one of another user (left alone), a missing
#   parent, a symbolic link, a .. component.
# FreeBSD only (stat -f, the rc scripts); everything it writes is in its own temporary directory, as root or not.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -10 | sed 's/^/         /'; }
[ "$(uname -s)" = FreeBSD ] || { echo "SKIP: not FreeBSD (the rc scripts and stat -f)"; exit 0; }
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_rcdirs.XXXXXX") || exit 1
trap 'rm -rf "$T"' EXIT
trap 'exit 130' INT TERM
ME=$(id -u)

# the stub rc.subr: run_rc_command runs its argument; id knows "svc" (the uid of this test, so that its directories are svc's) and "other"
cat > "$T/rc.subr" <<'EOF'
load_rc_config() { :; }
run_rc_command() { eval "$1"; }
warn() { echo "${name}: WARNING: $*" >&2; }
checkyesno() { eval "_v=\${$1}"; case "$_v" in [Yy][Ee][Ss]) return 0 ;; *) return 1 ;; esac; }
id() {
    case "$1:$2" in
        -u:svc) echo "$SVC_UID" ;;
        -g:svc|-gn:svc) echo svcg ;;
        -u:other) echo 4242 ;;
        -g:other|-gn:other) echo otherg ;;
        -u:*|-g:*|-gn:*) return 1 ;;
        *) command id "$@" ;;
    esac
}
install() { echo "install $*" >> "$RC_LOG"; }
mount() { [ "$1" = -p ] && return 0; echo "mount $*" >> "$RC_LOG"; }
su() { while [ $# -gt 0 ]; do [ "$1" = -c ] && { sh -c "$2"; return; }; shift; done; }
EOF
printf '#!/bin/sh\necho "program $*" >> "$RC_LOG"\n' > "$T/program"
chmod 755 "$T/program"
mkdir -p "$T/var/db"
for s in signer webadmin; do
    sed -e "s|^\. /etc/rc.subr$|. $T/rc.subr|" -e "s|/var/db|$T/var/db|g" -e "s|/var/run/|$T/var/run/|g" "$ROOT/packaging/freebsd/rc.d/karidns_$s" > "$T/rc_$s"
    grep -q "^\. $T/rc.subr$" "$T/rc_$s" || { echo "  [FAIL] rc.d/karidns_$s does not source /etc/rc.subr"; exit 1; }
done
same() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', wanted '$3')"; fi; }
# sig CMD WORKDIR [USERUID] [TMPFS]: run the signer's rc script (onestart's precmd or configtest) with work-dir WORKDIR (none: the default)
sig() {
    : > "$T/log"
    if [ "$2" = none ]; then : > "$T/s.conf"; else printf 'work-dir = %s\n' "$2" > "$T/s.conf"; fi
    SVC_UID=${3:-$ME} RC_LOG=$T/log karidns_signer_user=svc karidns_signer_config=$T/s.conf karidns_signer_wrapper=$T/program \
        karidns_signer_tmpfs=${4:-NO} sh "$T/rc_signer" "$1" > "$T/out" 2>&1
}
# made: the directories install was asked to make, one per line (the pid directory left out)
made() { awk '$1 == "install" { print $NF }' "$T/log" | grep -v '/var/run/' ; }

echo "-- karidns-signer: the default work-dir ($T/var/db standing for /var/db)"
if sig karidns_signer_prestart none; then ok "a fresh installation: the start goes on"; else bad "fresh installation refused" "$(cat "$T/out")"; fi
same "...it makes /var/db/karidns-signer and the work directory, the user's, 0700" "$(awk '$1 == "install" && $NF !~ /var\/run/ { sub(/^install /, ""); print }' "$T/log" | tr '\n' '|')" "-d -o svc -g svcg -m 0700 $T/var/db/karidns-signer|-d -o svc -g svcg -m 0700 $T/var/db/karidns-signer/work|"
grep -qx "install -d -o svc -g svcg -m 0755 $T/var/run/karidns_signer" "$T/log" && ok "...and the pid directory" || bad "no pid directory" "$(cat "$T/log")"
sig karidns_signer_configtest none
same "configtest on it makes nothing" "$(grep -c '^install' "$T/log")" 0
grep -q 'does not exist yet: start makes it' "$T/out" && grep -q '^program --check' "$T/log" && ok "...says the start makes the work directory, and runs --check" || bad "configtest, fresh" "$(cat "$T/out" "$T/log")"

echo "-- karidns-signer: an existing work-dir is never changed"
mkdir -p "$T/own/work" && chmod 700 "$T/own/work"
sig karidns_signer_prestart "$T/own/work" && [ -z "$(made)" ] && ok "a work-dir of the user, 0700: used as it is (no install)" || bad "own work-dir" "$(cat "$T/out" "$T/log")"
sig karidns_signer_prestart "$T/own/work" 4242 && bad "a work-dir of another user was accepted" || { [ -z "$(made)" ] && grep -q 'is not a directory of svc with mode 0700: it is left as it is' "$T/out" && ok "a work-dir of another user: refused, left as it is" || bad "work-dir of another user" "$(cat "$T/out" "$T/log")"; }
sig karidns_signer_configtest "$T/own/work" 4242 && bad "configtest accepted a work-dir of another user" || { [ -z "$(cat "$T/log")" ] && ok "...configtest refuses it too and changes nothing" || bad "configtest, another user" "$(cat "$T/log")"; }
chmod 755 "$T/own/work"
sig karidns_signer_prestart "$T/own/work" && bad "a work-dir with mode 0755 was accepted" || { [ "$(stat -f %Lp "$T/own/work")" = 755 ] && grep -q 'mode 755' "$T/out" && ok "a work-dir with mode 0755: refused, its mode left as it is" || bad "work-dir 0755" "$(cat "$T/out")"; }
chmod 700 "$T/own/work"
mkdir -p "$T/tm" && TM="$T/tm/stays"; [ -d "$TM" ] || mkdir "$TM"
sig karidns_signer_prestart "$TM/../work" && bad "a .. component was accepted" || { [ -z "$(made)" ] && grep -q '\. or \.\. component' "$T/out" && ok "a .. component: refused" || bad ".. component" "$(cat "$T/out")"; }

echo "-- karidns-signer: where a missing work-dir may be made"
W=/var/tmp/karidns-rcdirs-test-$$
[ -e "$W" ] && { bad "$W exists"; }
sig karidns_signer_prestart "$W" && same "work-dir in /var/tmp: only the work directory is made, never /var/tmp" "$(made | tr '\n' '|')" "$W|" || bad "work-dir in /var/tmp refused" "$(cat "$T/out")"
[ ! -e "$W" ] && ok "...(install is a stub: nothing was made on the host)" || bad "$W was made on the host"
sig karidns_signer_prestart "$T/nope/work" && bad "a work-dir with a missing parent was accepted" || { [ -z "$(made)" ] && grep -q "the parent $T/nope of work-dir .* does not exist: create it" "$T/out" && ok "a missing parent (not /var/db/karidns-signer): refused, nothing made" || bad "missing parent" "$(cat "$T/out" "$T/log")"; }
sig karidns_signer_prestart "relative/work" && bad "a relative work-dir was accepted" || { [ -z "$(made)" ] && grep -q 'is not an absolute path' "$T/out" && ok "a relative path: refused" || bad "relative path" "$(cat "$T/out")"; }
mkdir -p "$T/real" && ln -s "$T/real" "$T/link"
sig karidns_signer_prestart "$T/link/work" && bad "a work-dir through a symbolic link was accepted" || { [ -z "$(made)" ] && grep -q "$T/link is a symbolic link" "$T/out" && ok "a symbolic link in the path: refused, nothing made" || bad "symbolic link" "$(cat "$T/out")"; }
ln -s "$T/own/work" "$T/worklink"
sig karidns_signer_prestart "$T/worklink" && bad "a work-dir that is a symbolic link was accepted" || ok "a work-dir that is itself a symbolic link: refused"
: > "$T/afile"
sig karidns_signer_prestart "$T/afile" && bad "a file as work-dir was accepted" || { grep -q 'exists and is not a directory' "$T/out" && ok "a file in the place of the work directory: refused" || bad "file as work-dir" "$(cat "$T/out")"; }
sig karidns_signer_prestart "$T/own/new" "" YES && { grep -q "^install -d -o svc -g svcg -m 0700 $T/own/new$" "$T/log" && grep -q "^mount -t tmpfs .*mode=0700,uid=$ME.* tmpfs $T/own/new$" "$T/log" && ok "tmpfs: the work directory is made, then the tmpfs mounted on it" || bad "tmpfs" "$(cat "$T/log")"; } || bad "tmpfs start refused" "$(cat "$T/out")"

echo "-- karidns-webadmin: the directory of the TOTP key"
wa() {
    : > "$T/log"
    if [ "$2" = none ]; then : > "$T/w.conf"; else printf 'totp-key-file = %s\n' "$2" > "$T/w.conf"; fi
    SVC_UID=${3:-$ME} RC_LOG=$T/log karidns_webadmin_user=svc karidns_webadmin_config=$T/w.conf karidns_webadmin_wrapper=$T/program sh "$T/rc_webadmin" "$1" > "$T/out" 2>&1
}
wa karidns_webadmin_prestart none && same "the default (/var/db/karidns-webadmin): made at start, the user's, 0700" "$(made | tr '\n' '|')" "$T/var/db/karidns-webadmin|" || bad "webadmin default" "$(cat "$T/out")"
wa karidns_webadmin_configtest none
same "...configtest makes nothing" "$(grep -c '^install' "$T/log")" 0
grep -q 'does not exist yet: start makes it' "$T/out" && grep -q '^program --check' "$T/log" && ok "...says so and runs --check" || bad "webadmin configtest" "$(cat "$T/out" "$T/log")"
mkdir -p "$T/keys"
wa karidns_webadmin_prestart "$T/keys/totp.key" 4242 && [ -z "$(made)" ] && ok "an existing directory of another user: left alone" || bad "webadmin existing directory" "$(cat "$T/out" "$T/log")"
wa karidns_webadmin_prestart "$T/nope/keys/totp.key" && bad "webadmin: a missing parent was accepted" || { [ -z "$(made)" ] && grep -q 'does not exist: create it' "$T/out" && ok "a missing parent: refused, nothing made" || bad "webadmin missing parent" "$(cat "$T/out")"; }
wa karidns_webadmin_prestart "$T/link/keys/totp.key" && bad "webadmin: a symbolic link was accepted" || { [ -z "$(made)" ] && ok "a symbolic link in the path: refused" || bad "webadmin symbolic link" "$(cat "$T/log")"; }
wa karidns_webadmin_prestart "$T/keys/../k2/totp.key" && bad "webadmin: a .. component was accepted" || ok "a .. component: refused"

echo
echo "=== run_rc_service_dirs_test: $FAILS failed, $PASS passed ==="
[ "$FAILS" = 0 ]

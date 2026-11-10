#!/bin/sh
# run_signer_pkg_test.sh - the FreeBSD package of karidns-signer (packaging/freebsd/build_signer_pkg.sh, the rc script and the wrapper; 0.6.0 items C and E, M5).
#
# 1. the scripts parse (sh -n); the wrapper and the rc script have what the packaging relies on (no `daemon -u`, no ${name}_program variable);
# 2. the package is built in a temporary copy (npm ci --omit=dev --ignore-scripts) and looked at with pkg: name, version, the dependencies on node24 and
#    bind-tools, the files and their modes, the sample configuration and the manual, no test and no node_modules/.bin in it, the pre-install script (the group
#    and the user, the refusal without karidns-zone);
# 3. the package is unpacked into a temporary root and the program in that layout runs: --version, the `pg` module found, --check and a real daemon on a SQLite3
#    database (it starts, logs to stderr, stops on SIGTERM with status 0);
# 4. as root: the rc script itself (onestart with another user and a program wrapper of the test, the work directory and the pid directory it makes, the tmpfs
#    on the work directory, both pid files, the user of the daemon, the lines in syslog, configtest, reload = SIGHUP, onestop, the unmount).
# SKIP (exit 0, with the reason) for the parts without FreeBSD's pkg, the node24 and bind-tools packages, npm, the sqlite3 tool or the built karidns-zone /
# karicheck / karictl; the rc part without root, without the user nobody, or with a service of the host in /var/run/karidns_signer; the tmpfs part when the
# system refuses the mount (a jail); the syslog part when logger(1) does not reach /var/log/messages.
# Environment: ZONE (default ./karidns-zone), KARICHECK (default ./karicheck), KARICTL (default ./karictl).  Needs the network or the npm cache for `npm ci`
# (npm_config_prefer_offline is set).
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -12 | sed 's/^/         /'; }
same() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', wanted '$3')"; fi; }
done_() { echo; echo "=== run_signer_pkg_test: $FAILS failed, $PASS passed ==="; [ "$FAILS" = 0 ]; exit $?; }

echo "-- the scripts"
for f in packaging/freebsd/build_signer_pkg.sh packaging/freebsd/karidns-signer packaging/freebsd/rc.d/karidns_signer; do
    sh -n "$f" 2> /tmp/ksp_syntax.$$ && ok "$f parses" || bad "$f does not parse" "$(cat /tmp/ksp_syntax.$$)"
done
rm -f /tmp/ksp_syntax.$$
grep -q '^ulimit -c 0' packaging/freebsd/karidns-signer && ok "the wrapper switches core dumps off" || bad "the wrapper has no ulimit -c 0"
grep -q '^exec /usr/local/bin/node /usr/local/libexec/karidns-signer/signer/bin/karidns-signer.js "\$@"$' packaging/freebsd/karidns-signer && ok "...and starts the program with the fixed path of node" || bad "the wrapper does not exec the fixed node and program"
for k in PROVIDE REQUIRE KEYWORD; do grep -q "^# $k:" packaging/freebsd/rc.d/karidns_signer && ok "the rc script has $k" || bad "the rc script has no $k"; done
# rc.subr runs the command as ${name}_user with su(1): daemon(8) must not drop privileges itself (initgroups fails then); the pid files are in a directory of that user;
# ${name}_program is rc.subr's `command`
grep -Eq '^[^#]*daemon.* -u ' packaging/freebsd/rc.d/karidns_signer && bad "the rc script uses daemon -u (rc.subr already runs it as the service user)" || ok "the rc script does not use daemon -u"
grep -Eq '^[^#]*(^|[^_A-Za-z])karidns_signer_program' packaging/freebsd/rc.d/karidns_signer && bad "the rc script uses karidns_signer_program (rc.subr takes it for command)" || ok "the rc script does not use karidns_signer_program"
grep -q '^pidfile="\${rundir}/supervisor.pid"' packaging/freebsd/rc.d/karidns_signer && grep -q '^rundir="/var/run/\${name}"' packaging/freebsd/rc.d/karidns_signer && ok "the pid files are in /var/run/karidns_signer/" || bad "the pid files are not in /var/run/\${name}/"

command -v pkg > /dev/null 2>&1 || { echo "SKIP: pkg is not installed (this is not FreeBSD): the package parts"; done_; }
for p in node24 bind-tools; do
    pkg query '%n' "$p" > /dev/null 2>&1 || { echo "SKIP: the $p package is not installed: the package parts"; done_; }
done
command -v npm > /dev/null 2>&1 || { echo "SKIP: npm is not installed: the package parts"; done_; }
NODE=/usr/local/bin/node
[ -x "$NODE" ] || NODE=$(command -v node)
ZONE=${ZONE:-$ROOT/karidns-zone}
KARICHECK=${KARICHECK:-$ROOT/karicheck}
KARICTL=${KARICTL:-$ROOT/karictl}
case $ZONE in /*) ;; *) ZONE=$ROOT/${ZONE#./} ;; esac
case $KARICHECK in /*) ;; *) KARICHECK=$ROOT/${KARICHECK#./} ;; esac
case $KARICTL in /*) ;; *) KARICTL=$ROOT/${KARICTL#./} ;; esac

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_signer_pkg.XXXXXX") || exit 1
SRV=""
RCDIR=""
cleanup() {
    if [ -n "$SRV" ]; then kill -KILL "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null; fi
    if [ -n "$RCDIR" ]; then    # (the rc part: whatever is left of it)
        for p in $(cat /var/run/karidns_signer/child.pid /var/run/karidns_signer/supervisor.pid 2> /dev/null); do kill -KILL "$p" 2> /dev/null; done
        mount -p 2> /dev/null | awk -v d="$RCDIR/work" '$2 == d && $3 == "tmpfs" { found = 1 } END { exit !found }' && umount -f "$RCDIR/work" 2> /dev/null
        rm -rf /var/run/karidns_signer
    fi
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else chmod -R u+rwX "$T" 2>/dev/null; rm -rf "$T"; fi
}
trap cleanup EXIT
trap "exit 130" INT TERM

echo "-- the package"
# a copy of what the script reads, so that `npm ci` does not touch the working copy
mkdir -p "$T/src/signer" "$T/src/node" "$T/src/packaging" "$T/src/docs" "$T/out"
cp -R signer/bin signer/lib signer/package.json signer/package-lock.json "$T/src/signer/"
cp -R node/lib node/package.json "$T/src/node/"
cp -R packaging/freebsd packaging/version.sh "$T/src/packaging/" && cp VERSION "$T/src/"      # (version.sh: the number of the package, docs/RELEASING.md)
cp docs/karidns-signer.md "$T/src/docs/"
cp karidns-signer.conf.sample "$T/src/"
export npm_config_prefer_offline=true
if (cd "$T/src" && sh packaging/freebsd/build_signer_pkg.sh 9.9.9 "$T/out") > "$T/build.out" 2>&1; then ok "build_signer_pkg.sh builds the package"; else bad "build_signer_pkg.sh failed" "$(tail -15 "$T/build.out")"; done_; fi
PKG=$(ls "$T"/out/karidns-signer-9.9.9-*.pkg 2> /dev/null | head -1)
[ -n "$PKG" ] && ok "...named karidns-signer-<version>-<ABI>.pkg" || { bad "no package file" "$(ls "$T/out")"; done_; }
pkg info -F "$PKG" > "$T/info.out" 2>&1
grep -q '^Name *: karidns-signer$' "$T/info.out" && grep -q '^Version *: 9.9.9$' "$T/info.out" && ok "name and version" || bad "name / version" "$(head -5 "$T/info.out")"
grep -q '^Origin *: dns/karidns-signer$' "$T/info.out" && ok "origin dns/karidns-signer" || bad "origin"
pkg info -d -F "$PKG" 2> /dev/null | grep -q 'node24-' && ok "it depends on node24" || bad "no dependency on node24"
pkg info -d -F "$PKG" 2> /dev/null | grep -q 'bind-tools-' && ok "...and on bind-tools (dnssec-keygen, dnssec-signzone)" || bad "no dependency on bind-tools"
pkg info -l -F "$PKG" 2> /dev/null | tail -n +2 | sed 's/^[[:space:]]*//' > "$T/files.txt"
for f in /usr/local/sbin/karidns-signer /usr/local/etc/rc.d/karidns_signer /usr/local/etc/karidns/karidns-signer.conf.sample /usr/local/share/doc/karidns/karidns-signer.md \
         /usr/local/libexec/karidns-signer/signer/bin/karidns-signer.js /usr/local/libexec/karidns-signer/signer/lib/cli.js /usr/local/libexec/karidns-signer/signer/package.json \
         /usr/local/libexec/karidns-signer/node/lib/run.js /usr/local/libexec/karidns-signer/node/package.json /usr/local/libexec/karidns-signer/node_modules/pg/package.json; do
    grep -qx "$f" "$T/files.txt" && ok "the package holds $f" || bad "the package does not hold $f"
done
grep -Eq '^/usr/local/libexec/karidns-signer/(signer|node)/test/' "$T/files.txt" && bad "the package holds the test files of the program" || ok "no test file of the program in the package"
grep -q 'node_modules/\.bin' "$T/files.txt" && bad "the package holds node_modules/.bin" || ok "no node_modules/.bin (no link into the tree)"
grep -v '^/usr/local/\(sbin/karidns-signer\|etc/rc.d/karidns_signer\|etc/karidns/karidns-signer.conf.sample\|share/doc/karidns/karidns-signer.md\|libexec/karidns-signer/\)' "$T/files.txt" > "$T/other.txt"
[ ! -s "$T/other.txt" ] && ok "nothing outside the paths of the package" || bad "files outside the paths of the package" "$(head -5 "$T/other.txt")"
# the scripts and the user
mkdir "$T/root" && tar -xf "$PKG" -C "$T/root" 2> /dev/null
grep -q 'pw groupadd karidns-signer' "$T/root/+MANIFEST" && grep -q 'pw useradd karidns-signer .*-d /var/db/karidns-signer -s /usr/sbin/nologin' "$T/root/+MANIFEST" && ok "the pre-install script makes the group and the user (no login shell, no password)" || bad "pre-install script: no groupadd / useradd"
grep -q 'if \[ ! -x /usr/local/bin/karidns-zone \]' "$T/root/+MANIFEST" && grep -q 'exit 1' "$T/root/+MANIFEST" && ok "...and refuses to install without karidns-zone" || bad "pre-install script: no check of karidns-zone"
L=$T/root/usr/local/libexec/karidns-signer
same "the wrapper is mode 0555" "$(stat -f %Lp "$T/root/usr/local/sbin/karidns-signer")" 555
same "the rc script is mode 0555" "$(stat -f %Lp "$T/root/usr/local/etc/rc.d/karidns_signer")" 555
same "the program is mode 0555" "$(stat -f %Lp "$L/signer/bin/karidns-signer.js")" 555
same "the libraries are mode 0444" "$(stat -f %Lp "$L/signer/lib/cli.js")" 444
same "the sample configuration is mode 0644" "$(stat -f %Lp "$T/root/usr/local/etc/karidns/karidns-signer.conf.sample")" 644
cmp -s karidns-signer.conf.sample "$T/root/usr/local/etc/karidns/karidns-signer.conf.sample" && ok "the sample is the one of the repository" || bad "the sample differs"
cmp -s docs/karidns-signer.md "$T/root/usr/local/share/doc/karidns/karidns-signer.md" && ok "the manual is the one of the repository" || bad "the manual differs"
cmp -s packaging/freebsd/rc.d/karidns_signer "$T/root/usr/local/etc/rc.d/karidns_signer" && cmp -s packaging/freebsd/karidns-signer "$T/root/usr/local/sbin/karidns-signer" && ok "the rc script and the wrapper are the ones of the repository" || bad "the rc script or the wrapper differ"

echo "-- the program in the installed layout"
[ "$($NODE "$L/signer/bin/karidns-signer.js" --version 2>&1)" = "karidns-signer $(cat "$ROOT/VERSION")" ] && ok "--version" || bad "--version" "$($NODE "$L/signer/bin/karidns-signer.js" --version 2>&1)"
(cd "$L/signer" && $NODE -e 'import("pg").then((m) => process.exit(typeof (m.default ?? m).Client === "function" ? 0 : 1), () => process.exit(1))') && ok "the pg module is found from the installed program (node_modules next to signer/ and node/)" || bad "pg is not found in the installed layout"
command -v sqlite3 > /dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed: the installed program on a database"; done_; }
for b in "$ZONE" "$KARICHECK" "$KARICTL"; do [ -x "$b" ] || { echo "SKIP: $b is not built: the installed program on a database"; done_; }; done
"$ZONE" --version | grep -q sqlite3 || { echo "SKIP: $ZONE has no SQLite3 driver: the installed program on a database"; done_; }

cp "$ZONE" "$T/karidns-zone" && cp "$KARICHECK" "$T/karicheck" && cp "$KARICTL" "$T/karictl" && chmod 755 "$T/karidns-zone" "$T/karicheck" "$T/karictl"      # (the rc script part runs the service as another user: the binaries must be where it can enter)
DB=$T/zones.sqlite3
sqlite3 "$DB" < tests/db/pdns_schema.sqlite3.sql > /dev/null && sqlite3 "$DB" < db/karidns_ext.sqlite3.sql > /dev/null || { bad "cannot make the zone file"; done_; }
: > "$T/karictl.conf"
CONF=$T/karidns-signer.conf
WORK=$T/work
mkdir -m 700 "$WORK"
cat > "$CONF" <<EOF
database = sqlite3
sqlite-file = $DB
karictl-config = $T/karictl.conf
karidns-zone = $T/karidns-zone
karicheck = $T/karicheck
karictl = $T/karictl
work-dir = $WORK
workers = 1
log = stderr
EOF
APP="$NODE $L/signer/bin/karidns-signer.js -c $CONF"
$APP --check > "$T/check.out" 2> "$T/check.err" && ok "--check is fine" || bad "--check" "$(cat "$T/check.err" "$T/check.out")"
grep -q "^ok: dnssec-signzone " "$T/check.out" && grep -q "^ok: karidns-zone .*sqlite3" "$T/check.out" && ok "...and it ran the tools of bind-tools and karidns-zone" || bad "--check does not report the tools" "$(cat "$T/check.out")"
$APP > "$T/server.log" 2>&1 &
SRV=$!
i=0; while [ $i -lt 100 ] && ! grep -q "started" "$T/server.log" 2> /dev/null; do sleep 0.2; i=$((i + 1)); done
grep -q "karidns-signer [^ ]* started (sqlite3, 1 worker(s))" "$T/server.log" && ok "the daemon starts on the database" || { bad "the daemon did not start" "$(cat "$T/server.log")"; done_; }
kill -HUP "$SRV" 2> /dev/null
i=0; while [ $i -lt 50 ] && ! grep -q "configuration read again" "$T/server.log" 2> /dev/null; do sleep 0.2; i=$((i + 1)); done
grep -q "configuration read again" "$T/server.log" && ok "SIGHUP reads the configuration again" || bad "SIGHUP: no 'configuration read again'" "$(tail -5 "$T/server.log")"
kill -TERM "$SRV" 2> /dev/null
i=0; while [ $i -lt 100 ] && kill -0 "$SRV" 2> /dev/null; do sleep 0.1; i=$((i + 1)); done
kill -0 "$SRV" 2> /dev/null && { bad "the daemon did not stop after SIGTERM"; kill -KILL "$SRV"; } || { wait "$SRV" 2> /dev/null; same "SIGTERM stops it with status 0" "$?" 0; }
SRV=""

echo "-- the rc script (root)"
if [ "$(id -u)" != 0 ]; then echo "SKIP: not root: the rc script is started only as root"; done_; fi
id nobody > /dev/null 2>&1 || { echo "SKIP: no user nobody for the rc script test"; done_; }
[ -e /var/run/karidns_signer ] && { echo "SKIP: /var/run/karidns_signer exists (a real karidns_signer service?): the rc script test would use its directory"; done_; }
# the service user of the test is `nobody`: the files it uses are its own, and the directories above them can be entered
RCDIR=$T/rcdir
chmod 755 "$T" "$T/root" "$T/root/usr" "$T/root/usr/local" "$T/root/usr/local/libexec" "$L" 2> /dev/null
chown nobody "$DB" "$T"
mkdir "$RCDIR" && chown nobody "$RCDIR"
rmdir "$WORK"
cat > "$T/wrapper.sh" <<EOF
#!/bin/sh
exec $NODE $L/signer/bin/karidns-signer.js "\$@"
EOF
chmod 755 "$T/wrapper.sh"
sed -e "s|^work-dir = .*|work-dir = $RCDIR/work|" -e 's/^log = .*/log = daemon/' "$CONF" > "$T/rc.conf" && mv "$T/rc.conf" "$CONF"
chmod 644 "$CONF"
# a tmpfs on the work directory is the default of the rc script; a jail refuses the mount
TMPFS=NO
mkdir "$T/mnt_probe"
if mount -t tmpfs tmpfs "$T/mnt_probe" 2> "$T/mnt.err"; then umount "$T/mnt_probe"; TMPFS=YES; else echo "SKIP: the system refuses a tmpfs mount ($(head -1 "$T/mnt.err")): the tmpfs on the work directory (the rc script runs with karidns_signer_tmpfs=NO)"; fi
RC="env karidns_signer_user=nobody karidns_signer_config=$CONF karidns_signer_wrapper=$T/wrapper.sh karidns_signer_tmpfs=$TMPFS sh $ROOT/packaging/freebsd/rc.d/karidns_signer"
$RC oneconfigtest > "$T/rc_cfg.out" 2>&1 && ok "configtest runs --check as the service user" || bad "configtest" "$(cat "$T/rc_cfg.out")"
grep -q "the configuration is fine" "$T/rc_cfg.out" && ok "...and the configuration is fine" || bad "configtest output" "$(cat "$T/rc_cfg.out")"
[ -d "$RCDIR/work" ] && same "the work directory is made, mode 0700" "$(stat -f %Lp "$RCDIR/work")" 700 || bad "the work directory was not made"
same "...owned by the service user" "$(stat -f %Su "$RCDIR/work")" nobody
same "...and its parent is mode 0700" "$(stat -f %Lp "$RCDIR")" 700
# syslog: does a line of logger(1) reach /var/log/messages here?
SYSLOG=NO
logger -p daemon.notice -t karidns-signer-probe "probe $$" 2> /dev/null
i=0; while [ $i -lt 20 ]; do grep -q "karidns-signer-probe.*probe $$" /var/log/messages 2> /dev/null && { SYSLOG=YES; break; }; sleep 0.2; i=$((i + 1)); done
[ $SYSLOG = YES ] || echo "SKIP: a line of logger(1) does not reach /var/log/messages (no syslogd here): the syslog lines of the daemon"
$RC onestart > "$T/rc_start.out" 2>&1 && ok "onestart" || { bad "onestart" "$(cat "$T/rc_start.out")"; done_; }
SUP=$(cat /var/run/karidns_signer/supervisor.pid 2> /dev/null); CHILD=""
i=0; while [ $i -lt 100 ] && [ -z "$CHILD" ]; do CHILD=$(cat /var/run/karidns_signer/child.pid 2> /dev/null); sleep 0.1; i=$((i + 1)); done
{ [ -n "$SUP" ] && kill -0 "$SUP" 2> /dev/null; } && ok "the supervisor pid file names a live process" || bad "no live supervisor ($SUP)"
{ [ -n "$CHILD" ] && kill -0 "$CHILD" 2> /dev/null; } && ok "the child pid file names a live process" || bad "no live child ($CHILD)"
same "the pid directory is the service user's" "$(stat -f %Su /var/run/karidns_signer)" nobody
same "the daemon runs as the service user" "$(ps -o user= -p "$CHILD" 2> /dev/null | tr -d ' ')" nobody
$RC onestatus > /dev/null 2>&1 && ok "status finds it" || bad "status"
if [ $SYSLOG = YES ]; then
    i=0; while [ $i -lt 100 ] && ! grep -q "karidns-signer.*karidns-signer [^ ]* started (sqlite3" /var/log/messages 2> /dev/null; do sleep 0.2; i=$((i + 1)); done
    grep "karidns-signer" /var/log/messages | tail -20 | grep -q "started (sqlite3, 1 worker(s))" && ok "the daemon logs to syslog (it started)" || bad "no 'started' line in /var/log/messages" "$(tail -3 /var/log/messages)"
fi
if [ $TMPFS = YES ]; then
    mount -p 2> /dev/null | awk -v d="$RCDIR/work" '$2 == d && $3 == "tmpfs" { found = 1 } END { exit !found }' && ok "a tmpfs is mounted on the work directory" || bad "no tmpfs on the work directory"
    same "...owned by the service user, mode 0700" "$(stat -f '%Su %Lp' "$RCDIR/work")" "nobody 700"
fi
# reload = SIGHUP: the same process goes on and reads the configuration again
$RC onereload > "$T/rc_reload.out" 2>&1 && ok "reload" || bad "reload" "$(cat "$T/rc_reload.out")"
sleep 1
[ $SYSLOG = YES ] && { grep "karidns-signer" /var/log/messages | tail -20 | grep -q "configuration read again" && ok "...the daemon read the configuration again (SIGHUP)" || bad "no 'configuration read again' in /var/log/messages"; }
{ kill -0 "$CHILD" 2> /dev/null && [ "$(cat /var/run/karidns_signer/child.pid)" = "$CHILD" ]; } && ok "the same process went on (no restart)" || bad "the process was restarted by the reload"
$RC onestop > "$T/rc_stop.out" 2>&1 && ok "onestop" || bad "onestop" "$(cat "$T/rc_stop.out")"
i=0; while [ $i -lt 100 ] && kill -0 "$CHILD" 2> /dev/null; do sleep 0.1; i=$((i + 1)); done
kill -0 "$CHILD" 2> /dev/null && { bad "the daemon is still running"; kill -KILL "$CHILD" "$SUP" 2> /dev/null; } || ok "the daemon is gone"
kill -0 "$SUP" 2> /dev/null && { bad "the supervisor is still running"; kill -KILL "$SUP" 2> /dev/null; } || ok "...and the supervisor"
[ ! -e /var/run/karidns_signer/child.pid ] && ok "the child pid file is removed after the stop" || bad "child.pid is left"
if [ $TMPFS = YES ]; then
    mount -p 2> /dev/null | awk -v d="$RCDIR/work" '$2 == d && $3 == "tmpfs" { found = 1 } END { exit !found }' && bad "the tmpfs is still mounted after the stop" || ok "the tmpfs is unmounted after the stop"
fi
same "the work directory holds nothing after the stop" "$(ls -A "$RCDIR/work" | wc -l | tr -d ' ')" 0
rm -rf /var/run/karidns_signer
$RC onereload > /dev/null 2>&1 && bad "reload of a service that is not running succeeded" || ok "reload says 'not running' and fails when nothing runs"
done_

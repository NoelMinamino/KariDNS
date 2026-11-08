#!/bin/sh
# run_webadmin_pkg_test.sh - the FreeBSD package of karidns-webadmin (packaging/freebsd/build_webadmin_pkg.sh, the rc script and the wrapper; 0.6.0 items D and E, M5).
#
# 1. the scripts parse (sh -n);
# 2. the package is built in a temporary copy (npm ci --omit=dev --ignore-scripts) and looked at with pkg: name, version, the dependency on node24, the files and their
#    modes, the sample configuration and the manuals, no test and no node_modules/.bin in it, the pre-install script (the user, the refusal without karidns-zone);
# 3. the package is unpacked into a temporary root and the program in that layout runs: --version, the `pg` module found, --check, --create-admin and a real
#    server on a real port (login, /health, SIGTERM);
# 4. as root: the rc script itself (onestart with another user and a program wrapper of the test, the directories it makes, both pid files, configtest, reload =
#    SIGHUP reads the configuration again, onestop).
# SKIP (exit 0, with the reason) for the parts without FreeBSD's pkg, the node24 package, npm, the sqlite3 tool or the built karidns-zone / karicheck.
# Environment: ZONE (default ./karidns-zone), KARICHECK (default ./karicheck).  Needs the network or the npm cache for `npm ci` (npm_config_prefer_offline is set).
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/tests/lib_proc.sh"
cd "$ROOT" || exit 1

PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -12 | sed 's/^/         /'; }
same() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', wanted '$3')"; fi; }
done_() { echo; echo "=== run_webadmin_pkg_test: $FAILS failed, $PASS passed ==="; [ "$FAILS" = 0 ]; exit $?; }

echo "-- the scripts"
for f in packaging/freebsd/build_webadmin_pkg.sh packaging/freebsd/karidns-webadmin packaging/freebsd/rc.d/karidns_webadmin; do
    sh -n "$f" 2> /tmp/kwp_syntax.$$ && ok "$f parses" || bad "$f does not parse" "$(cat /tmp/kwp_syntax.$$)"
done
rm -f /tmp/kwp_syntax.$$
grep -q '^ulimit -c 0' packaging/freebsd/karidns-webadmin && ok "the wrapper switches core dumps off" || bad "the wrapper has no ulimit -c 0"
grep -q '^exec /usr/local/bin/node /usr/local/libexec/karidns-webadmin/webadmin/bin/karidns-webadmin.js "\$@"$' packaging/freebsd/karidns-webadmin && ok "...and starts the program with the fixed path of node" || bad "the wrapper does not exec the fixed node and program"
for k in PROVIDE REQUIRE KEYWORD; do grep -q "^# $k:" packaging/freebsd/rc.d/karidns_webadmin && ok "the rc script has $k" || bad "the rc script has no $k"; done

command -v pkg > /dev/null 2>&1 || { echo "SKIP: pkg is not installed (this is not FreeBSD): the package parts"; done_; }
pkg query '%n' node24 > /dev/null 2>&1 || { echo "SKIP: the node24 package is not installed: the package parts"; done_; }
command -v npm > /dev/null 2>&1 || { echo "SKIP: npm is not installed: the package parts"; done_; }
NODE=/usr/local/bin/node
[ -x "$NODE" ] || NODE=$(command -v node)
ZONE=${ZONE:-$ROOT/karidns-zone}
KARICHECK=${KARICHECK:-$ROOT/karicheck}
case $ZONE in /*) ;; *) ZONE=$ROOT/${ZONE#./} ;; esac
case $KARICHECK in /*) ;; *) KARICHECK=$ROOT/${KARICHECK#./} ;; esac

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_webadmin_pkg.XXXXXX") || exit 1
SRV=""
cleanup() {
    if [ -n "$SRV" ]; then kill -KILL "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null; fi
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else chmod -R u+rwX "$T" 2>/dev/null; rm -rf "$T"; fi
}
trap cleanup EXIT
trap "exit 130" INT TERM

echo "-- the package"
# a copy of what the script reads, so that `npm ci` does not touch the working copy
mkdir -p "$T/src/webadmin" "$T/src/node" "$T/src/packaging" "$T/src/docs" "$T/out"
cp -R webadmin/bin webadmin/lib webadmin/package.json webadmin/package-lock.json "$T/src/webadmin/"
cp -R node/lib node/package.json "$T/src/node/"
cp -R packaging/freebsd "$T/src/packaging/"
cp docs/karidns-webadmin.md docs/karidns-api.md "$T/src/docs/"
cp karidns-webadmin.conf.sample "$T/src/"
export npm_config_prefer_offline=true
if (cd "$T/src" && sh packaging/freebsd/build_webadmin_pkg.sh 9.9.9 "$T/out") > "$T/build.out" 2>&1; then ok "build_webadmin_pkg.sh builds the package"; else bad "build_webadmin_pkg.sh failed" "$(tail -15 "$T/build.out")"; done_; fi
PKG=$(ls "$T"/out/karidns-webadmin-9.9.9-*.pkg 2> /dev/null | head -1)
[ -n "$PKG" ] && ok "...named karidns-webadmin-<version>-<ABI>.pkg" || { bad "no package file" "$(ls "$T/out")"; done_; }
pkg info -F "$PKG" > "$T/info.out" 2>&1
grep -q '^Name *: karidns-webadmin$' "$T/info.out" && grep -q '^Version *: 9.9.9$' "$T/info.out" && ok "name and version" || bad "name / version" "$(head -5 "$T/info.out")"
grep -q '^Origin *: dns/karidns-webadmin$' "$T/info.out" && ok "origin dns/karidns-webadmin" || bad "origin"
pkg info -d -F "$PKG" 2> /dev/null | grep -q 'node24-' && ok "it depends on node24" || bad "no dependency on node24"
pkg info -d -F "$PKG" 2> /dev/null | grep -q 'bind-tools' && bad "it depends on bind-tools (only the signer needs them)" || ok "...and on nothing else it does not use"
pkg info -l -F "$PKG" 2> /dev/null | tail -n +2 | sed 's/^[[:space:]]*//' > "$T/files.txt"
for f in /usr/local/sbin/karidns-webadmin /usr/local/etc/rc.d/karidns_webadmin /usr/local/etc/karidns/karidns-webadmin.conf.sample /usr/local/share/doc/karidns/karidns-webadmin.md \
         /usr/local/share/doc/karidns/karidns-api.md /usr/local/libexec/karidns-webadmin/webadmin/bin/karidns-webadmin.js /usr/local/libexec/karidns-webadmin/webadmin/lib/cli.js \
         /usr/local/libexec/karidns-webadmin/node/lib/run.js /usr/local/libexec/karidns-webadmin/node/package.json /usr/local/libexec/karidns-webadmin/node_modules/pg/package.json; do
    grep -qx "$f" "$T/files.txt" && ok "the package holds $f" || bad "the package does not hold $f"
done
grep -Eq '^/usr/local/libexec/karidns-webadmin/(webadmin|node)/test/' "$T/files.txt" && bad "the package holds the test files of the program" || ok "no test file of the program in the package"
grep -q 'node_modules/\.bin' "$T/files.txt" && bad "the package holds node_modules/.bin" || ok "no node_modules/.bin (no link into the tree)"
grep -v '^/usr/local/\(sbin/karidns-webadmin\|etc/rc.d/karidns_webadmin\|etc/karidns/karidns-webadmin.conf.sample\|share/doc/karidns/karidns-\(webadmin\|api\).md\|libexec/karidns-webadmin/\)' "$T/files.txt" > "$T/other.txt"
[ ! -s "$T/other.txt" ] && ok "nothing outside the paths of the package" || bad "files outside the paths of the package" "$(head -5 "$T/other.txt")"
# the scripts and the user
mkdir "$T/root" && tar -xf "$PKG" -C "$T/root" 2> /dev/null
grep -q 'pw useradd karidns-webadmin .*-d /var/db/karidns-webadmin -s /usr/sbin/nologin' "$T/root/+MANIFEST" && ok "the pre-install script makes the user (no login shell, no password)" || bad "pre-install script: no useradd"
grep -q 'karidns-zone' "$T/root/+MANIFEST" && grep -q 'exit 1' "$T/root/+MANIFEST" && ok "...and refuses to install without karidns-zone and karicheck" || bad "pre-install script: no check of karidns-zone"
L=$T/root/usr/local/libexec/karidns-webadmin
same "the wrapper is mode 0555" "$(stat -f %Lp "$T/root/usr/local/sbin/karidns-webadmin")" 555
same "the rc script is mode 0555" "$(stat -f %Lp "$T/root/usr/local/etc/rc.d/karidns_webadmin")" 555
same "the program is mode 0555" "$(stat -f %Lp "$L/webadmin/bin/karidns-webadmin.js")" 555
same "the libraries are mode 0444" "$(stat -f %Lp "$L/webadmin/lib/cli.js")" 444
same "the sample configuration is mode 0644" "$(stat -f %Lp "$T/root/usr/local/etc/karidns/karidns-webadmin.conf.sample")" 644
cmp -s karidns-webadmin.conf.sample "$T/root/usr/local/etc/karidns/karidns-webadmin.conf.sample" && ok "the sample is the one of the repository" || bad "the sample differs"

echo "-- the program in the installed layout"
[ "$($NODE "$L/webadmin/bin/karidns-webadmin.js" --version 2>&1)" = "karidns-webadmin 0.6.0" ] && ok "--version" || bad "--version" "$($NODE "$L/webadmin/bin/karidns-webadmin.js" --version 2>&1)"
(cd "$L/webadmin" && $NODE -e 'import("pg").then((m) => process.exit(typeof (m.default ?? m).Pool === "function" ? 0 : 1), () => process.exit(1))') && ok "the pg module is found from the installed program (node_modules next to webadmin/ and node/)" || bad "pg is not found in the installed layout"
command -v sqlite3 > /dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed: the installed program on a database"; done_; }
[ -x "$ZONE" ] && [ -x "$KARICHECK" ] || { echo "SKIP: $ZONE or $KARICHECK is not built: the installed program on a database"; done_; }
"$ZONE" --version | grep -q sqlite3 || { echo "SKIP: $ZONE has no SQLite3 driver: the installed program on a database"; done_; }

cp "$ZONE" "$T/karidns-zone" && cp "$KARICHECK" "$T/karicheck" && chmod 755 "$T/karidns-zone" "$T/karicheck"      # (the rc script part runs the service as another user: the binaries must be where it can enter)
DB=$T/zones.sqlite3
AUTH=$T/auth.sqlite3
sqlite3 "$DB" < tests/db/pdns_schema.sqlite3.sql > /dev/null && sqlite3 "$DB" < db/karidns_ext.sqlite3.sql > /dev/null && sqlite3 "$DB" < db/karidns_audit.sqlite3.sql > /dev/null || { bad "cannot make the zone file"; done_; }
sqlite3 "$AUTH" < db/karidns_auth.sqlite3.sql > /dev/null || { bad "cannot make the auth file"; done_; }
chmod 600 "$AUTH"
PORT=$(kari_port 0 $((22000 + $$ % 20000)))
CONF=$T/karidns-webadmin.conf
cat > "$CONF" <<EOF
listen = 127.0.0.1:$PORT
public-origin = http://127.0.0.1:$PORT
database = sqlite3
sqlite-file = $DB
auth-file = $AUTH
totp-key-file = $T/key/totp.key
karidns-zone = $T/karidns-zone
karicheck = $T/karicheck
scrypt-ln = 14
require-totp = none
log = stderr
EOF
mkdir -p "$T/key"
APP="$NODE $L/webadmin/bin/karidns-webadmin.js -c $CONF"
$APP --check > "$T/check.out" 2> "$T/check.err" && ok "--check is fine" || bad "--check" "$(cat "$T/check.err" "$T/check.out")"
$APP --create-admin admin > "$T/admin.out" 2> "$T/admin.err" && ok "--create-admin" || bad "--create-admin" "$(cat "$T/admin.err")"
PW=$(sed -n 's/^password (shown once): //p' "$T/admin.out")
$APP > "$T/server.log" 2>&1 &
SRV=$!
i=0; while [ $i -lt 100 ] && ! grep -q "started" "$T/server.log" 2> /dev/null; do sleep 0.2; i=$((i + 1)); done
grep -q "karidns-webadmin 0.6.0 started" "$T/server.log" && ok "the server starts" || { bad "the server did not start" "$(cat "$T/server.log")"; done_; }
cat > "$T/probe.mjs" <<'EOF'
const base = process.argv[2];
const h = await fetch(`${base}/health`);
const r = await fetch(`${base}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ user: process.argv[3], password: process.argv[4] }) });
const me = await fetch(`${base}/auth/me`, { headers: { Cookie: /karidns_session=[^;]+/.exec(r.headers.get('set-cookie'))[0] } });
console.log(h.status, r.status, me.status, (await me.json()).capabilities?.global);
EOF
same "/health, the login and /auth/me through the installed program" "$($NODE "$T/probe.mjs" "http://127.0.0.1:$PORT/api/v1" admin "$PW" 2>&1)" "200 200 200 true"
kill -TERM "$SRV" 2> /dev/null
i=0; while [ $i -lt 100 ] && kill -0 "$SRV" 2> /dev/null; do sleep 0.1; i=$((i + 1)); done
kill -0 "$SRV" 2> /dev/null && { bad "the server did not stop after SIGTERM"; kill -KILL "$SRV"; } || { wait "$SRV" 2> /dev/null; same "SIGTERM stops it with status 0" "$?" 0; }
SRV=""
same "the TOTP key file was made with mode 0600" "$(stat -f %Lp "$T/key/totp.key")" 600

echo "-- the rc script (root)"
if [ "$(id -u)" != 0 ]; then echo "SKIP: not root: the rc script is started only as root"; done_; fi
id nobody > /dev/null 2>&1 || { echo "SKIP: no user nobody for the rc script test"; done_; }
[ -e /var/run/karidns_webadmin ] && { echo "SKIP: /var/run/karidns_webadmin exists (a real karidns_webadmin service?): the rc script test would use its directory"; done_; }
# the service user of the test is `nobody`: the files it uses are its own, and the directories above them can be entered
chown nobody "$DB" "$AUTH"
chown nobody "$T/key" && rm -f "$T/key/totp.key"
chmod 755 "$T" "$T/root" "$T/root/usr" "$T/root/usr/local" "$T/root/usr/local/libexec" "$L" 2> /dev/null
chown nobody "$T"
KEYDIR=$T/rcdir/keys
cat > "$T/wrapper.sh" <<EOF
#!/bin/sh
exec $NODE $L/webadmin/bin/karidns-webadmin.js "\$@"
EOF
chmod 755 "$T/wrapper.sh"
sed -e "s|^totp-key-file = .*|totp-key-file = $KEYDIR/totp.key|" -e 's/^log = .*/log = stderr/' "$CONF" > "$T/rc.conf" && mv "$T/rc.conf" "$CONF"
chmod 644 "$CONF"
RC="env karidns_webadmin_user=nobody karidns_webadmin_config=$CONF karidns_webadmin_wrapper=$T/wrapper.sh sh $ROOT/packaging/freebsd/rc.d/karidns_webadmin"
mkdir -p "$T/rcdir" && chown nobody "$T/rcdir"
$RC oneconfigtest > "$T/rc_cfg.out" 2>&1 && ok "configtest runs --check as the service user" || bad "configtest" "$(cat "$T/rc_cfg.out")"
grep -q "the configuration is fine" "$T/rc_cfg.out" && ok "...and the configuration is fine" || bad "configtest output" "$(cat "$T/rc_cfg.out")"
[ -d "$KEYDIR" ] && same "the directory of the TOTP key is made, mode 0700" "$(stat -f %Lp "$KEYDIR")" 700 || bad "the directory of the TOTP key was not made"
same "...owned by the service user" "$(stat -f %Su "$KEYDIR")" nobody
$RC onestart > "$T/rc_start.out" 2>&1 && ok "onestart" || bad "onestart" "$(cat "$T/rc_start.out")"
i=0; while [ $i -lt 100 ] && ! $NODE -e "fetch('http://127.0.0.1:$PORT/api/v1/health').then((r) => process.exit(r.status === 200 ? 0 : 1), () => process.exit(1))"; do sleep 0.2; i=$((i + 1)); done
$NODE -e "fetch('http://127.0.0.1:$PORT/api/v1/health').then((r) => process.exit(r.status === 200 ? 0 : 1), () => process.exit(1))" && ok "the daemon answers /health" || bad "the daemon does not answer" "$(cat "$T/rc_start.out")"
SUP=$(cat /var/run/karidns_webadmin/supervisor.pid 2> /dev/null); CHILD=$(cat /var/run/karidns_webadmin/child.pid 2> /dev/null)
{ [ -n "$SUP" ] && kill -0 "$SUP" 2> /dev/null; } && ok "the supervisor pid file names a live process" || bad "no live supervisor ($SUP)"
{ [ -n "$CHILD" ] && kill -0 "$CHILD" 2> /dev/null; } && ok "the child pid file names a live process" || bad "no live child ($CHILD)"
same "the pid directory is the service user's" "$(stat -f %Su /var/run/karidns_webadmin)" nobody
same "the daemon runs as the service user" "$(ps -o user= -p "$CHILD" 2> /dev/null | tr -d ' ')" nobody
$RC onestatus > /dev/null 2>&1 && ok "status finds it" || bad "status"
# reload = SIGHUP: public-origin is read again (a login that names the new origin is refused before, accepted after)
# the password goes in the environment: as an argument one that starts with '-' (it is random base64url) is read by node as an option
login() { KW_PW="$PW" $NODE -e "fetch('http://127.0.0.1:$PORT/api/v1/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: '$1' }, body: JSON.stringify({ user: 'admin', password: process.env.KW_PW }) }).then((r) => console.log(r.status))"; }
same "a login with the origin of the new configuration is refused at first" "$(login http://127.0.0.1:$((PORT + 1)))" 403
sed -i '' "s|^public-origin = .*|public-origin = http://127.0.0.1:$((PORT + 1))|" "$CONF"
$RC onereload > "$T/rc_reload.out" 2>&1 && ok "reload" || bad "reload" "$(cat "$T/rc_reload.out")"
sleep 1
same "...and accepted after the reload (SIGHUP read the configuration again)" "$(login http://127.0.0.1:$((PORT + 1)))" 200
{ kill -0 "$CHILD" 2> /dev/null && [ "$(cat /var/run/karidns_webadmin/child.pid)" = "$CHILD" ]; } && ok "the same process went on (no restart)" || bad "the process was restarted by the reload"
$RC onestop > "$T/rc_stop.out" 2>&1 && ok "onestop" || bad "onestop" "$(cat "$T/rc_stop.out")"
i=0; while [ $i -lt 100 ] && kill -0 "$CHILD" 2> /dev/null; do sleep 0.1; i=$((i + 1)); done
kill -0 "$CHILD" 2> /dev/null && { bad "the daemon is still running"; kill -KILL "$CHILD" "$SUP" 2> /dev/null; } || ok "the daemon is gone"
kill -0 "$SUP" 2> /dev/null && { bad "the supervisor is still running"; kill -KILL "$SUP" 2> /dev/null; } || ok "...and the supervisor"
[ ! -e /var/run/karidns_webadmin/child.pid ] && ok "the child pid file is removed after the stop" || bad "child.pid is left"
rm -rf /var/run/karidns_webadmin
$RC onereload > /dev/null 2>&1 && bad "reload of a service that is not running succeeded" || ok "reload says 'not running' and fails when nothing runs"
done_

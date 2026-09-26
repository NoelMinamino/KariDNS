#!/bin/sh
# =============================================================================
# KariDNS non-root startup test
#
# karidns can be started directly as an unprivileged user (or as root, dropping
# to "user"). Resources that such a user cannot use must make startup fail
# with a clear error instead of running half-broken:
#   - port < 1024, or a port already in use (UDP and TCP)
#   - a log file / pid file / control socket in a directory it cannot write
#   - options { user } / program-user naming a different user
# All of these are checked before daemonize(), so they also fail with a
# non-zero exit status in daemon mode.
#
# Run as root, the karidns side runs as "nobody" (via su -m); run as a normal
# user, it runs as that user.
# =============================================================================
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/.."
[ -x "$ROOT/karidns" ] && [ -x "$ROOT/dag" ] || make -C "$ROOT" karidns dag >/dev/null

TMP="$(mktemp -d /tmp/karidns_nonroot.XXXXXX)"
chmod 755 "$TMP"
PIDS=""
cleanup() {
    for p in $PIDS; do kill -TERM "$p" 2>/dev/null; done
    sleep 0.3
    for p in $PIDS; do kill -9 "$p" 2>/dev/null; done
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

# the unprivileged side needs its own copies (the checkout may not be
# reachable by "nobody", e.g. under /root)
cp "$ROOT/karidns" "$ROOT/dag" "$TMP/"
chmod 755 "$TMP/karidns" "$TMP/dag"
KARIDNS="$TMP/karidns"
DAG="$TMP/dag"

# as_user <cmd> [args...]: run cmd as $RUN_USER. perl drops uid/gid and exec()s,
# so the pid seen by the shell is karidns itself (kill / wait work directly).
if [ "$(id -u)" -eq 0 ]; then
    RUN_USER=nobody
    as_user() {
        perl -e 'my @pw = getpwnam(shift) or die "no such user\n";
                 $( = $pw[3]; $) = "$pw[3] $pw[3]";
                 ($<, $>) = ($pw[2], $pw[2]);
                 die "privilege drop failed\n" if $< != $pw[2] || $> != $pw[2];
                 exec { $ARGV[0] } @ARGV or die "exec: $!\n";' "$RUN_USER" "$@"
    }
else
    RUN_USER="$(id -un)"
    as_user() { "$@"; }
fi
OTHER_USER=root
[ "$RUN_USER" = root ] && OTHER_USER=nobody

mkdir -p "$TMP/run" "$TMP/log"
chown "$RUN_USER" "$TMP/run" "$TMP/log" 2>/dev/null || true
touch "$TMP/not_a_dir"

cat > "$TMP/t.zone" <<'EOF'
$TTL 300
@   IN SOA ns1.t.test. hostmaster.t.test. 1 3600 600 86400 300
    IN NS  ns1.t.test.
ns1 IN A   127.0.0.1
www IN A   192.0.2.1
EOF
chmod 644 "$TMP/t.zone"

PASS=0
FAILS=0
ok()   { echo "  [OK] $1"; PASS=$((PASS + 1)); }
fail() { echo "  [FAIL] $1"; FAILS=$((FAILS + 1)); }

# free_port: print a free high port (UDP and TCP)
free_port() {
    perl -MIO::Socket::INET -e '
        for (1..200) { my $p = 20000 + int(rand(20000));
            my $u = IO::Socket::INET->new(Proto=>"udp", LocalAddr=>"127.0.0.1", LocalPort=>$p) or next;
            my $t = IO::Socket::INET->new(Proto=>"tcp", LocalAddr=>"127.0.0.1", LocalPort=>$p, Listen=>1) or next;
            print $p; exit 0 } exit 1'
}
PORT=$(free_port)
[ -n "$PORT" ] || { echo "FAIL: no free port"; exit 1; }

# write_conf <file> <options-body> [extra top-level text]
write_conf() {
    cat > "$1" <<EOF
options {
    bind-address { 127.0.0.1; };
    $2
};
zone "t.test" { type master; file "$TMP/t.zone"; };
${3:-}
EOF
    chmod 644 "$1"
}

# expect_refused <label> <expected message fragment> <karidns args...>
expect_refused() {
    label="$1"; want="$2"; shift 2
    out="$TMP/out.$$"
    as_user "$KARIDNS" "$@" > "$out" 2>&1 &
    p=$!
    PIDS="$PIDS $p"
    i=0; while kill -0 $p 2>/dev/null && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
    if kill -0 $p 2>/dev/null; then
        fail "$label: karidns kept running"
        kill -TERM $p 2>/dev/null
        return
    fi
    wait $p; rc=$?
    if [ $rc -eq 0 ]; then
        fail "$label: exit status 0"
    elif ! grep -q -- "$want" "$out"; then
        fail "$label: message '$want' not found"; sed 's/^/      /' "$out"
    else
        ok "$label (exit $rc)"
    fi
    rm -f "$out"
}

echo "[*] karidns runs as '$RUN_USER' (uid $(id -u "$RUN_USER")), port $PORT"

# -----------------------------------------------------------------------------
echo "[1] start as '$RUN_USER' with user \"$RUN_USER\", high port, own log/pid/control paths"
write_conf "$TMP/ok.conf" "port $PORT; user \"$RUN_USER\"; pid-file \"$TMP/run/k.pid\";" "
control-channel { socket \"$TMP/run/ctl.sock\"; algorithm hmac-sha256; secret \"dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl\"; };
logging {
    channel q { file \"$TMP/log/queries.log\"; print-time yes; };
    category queries { q; };
};"
as_user "$KARIDNS" -f "$TMP/ok.conf" > "$TMP/ok.out" 2>&1 &
OKPID=$!
PIDS="$PIDS $OKPID"
up=0
i=0
while [ $i -lt 50 ]; do
    case "$("$DAG" @127.0.0.1 -p "$PORT" t.test SOA +time=1 +tries=1 +short 2>/dev/null)" in
        *hostmaster*) up=1; break ;;
    esac
    kill -0 $OKPID 2>/dev/null || break
    sleep 0.1; i=$((i + 1))
done
if [ $up -eq 1 ]; then
    ok "answers over UDP"
    case "$("$DAG" @127.0.0.1 -p "$PORT" www.t.test A +tcp +time=1 +tries=1 +short 2>/dev/null)" in
        *192.0.2.1*) ok "answers over TCP" ;;
        *) fail "no TCP answer" ;;
    esac
    [ -f "$TMP/log/queries.log" ] && ok "log file created" || fail "log file missing"
    [ -s "$TMP/run/k.pid" ] && ok "pid file written" || fail "pid file missing"
    [ -S "$TMP/run/ctl.sock" ] && ok "control socket bound" || fail "control socket missing"
    owner=$(ls -l "$TMP/log/queries.log" 2>/dev/null | awk '{print $3}')
    [ "$owner" = "$RUN_USER" ] && ok "log file owned by $RUN_USER" || fail "log file owner is '$owner'"

else
    fail "karidns as '$RUN_USER' did not come up"
    sed 's/^/      /' "$TMP/ok.out"
fi
kill -TERM $OKPID 2>/dev/null
i=0; while kill -0 $OKPID 2>/dev/null && [ $i -lt 30 ]; do sleep 0.1; i=$((i + 1)); done

# -----------------------------------------------------------------------------
echo "[2] no user/group directive: runs as the invoking user"
write_conf "$TMP/nouser.conf" "port $PORT;"
as_user "$KARIDNS" -f "$TMP/nouser.conf" > "$TMP/nouser.out" 2>&1 &
NPID=$!
PIDS="$PIDS $NPID"
up=0; i=0
while [ $i -lt 50 ]; do
    case "$("$DAG" @127.0.0.1 -p "$PORT" t.test SOA +time=1 +tries=1 +short 2>/dev/null)" in
        *hostmaster*) up=1; break ;;
    esac
    kill -0 $NPID 2>/dev/null || break
    sleep 0.1; i=$((i + 1))
done
[ $up -eq 1 ] && ok "answers without 'user'" || { fail "did not come up without 'user'"; sed 's/^/      /' "$TMP/nouser.out"; }
kill -TERM $NPID 2>/dev/null
i=0; while kill -0 $NPID 2>/dev/null && [ $i -lt 30 ]; do sleep 0.1; i=$((i + 1)); done

# -----------------------------------------------------------------------------
echo "[3] resources the user cannot use are refused"
write_conf "$TMP/p53.conf" "port 53; user \"$RUN_USER\";"
expect_refused "port 53 (foreground)" "ports below 1024" -f "$TMP/p53.conf"
write_conf "$TMP/p53d.conf" "port 53; user \"$RUN_USER\"; pid-file \"$TMP/run/d.pid\";"
expect_refused "port 53 (daemon mode)" "ports below 1024" "$TMP/p53d.conf"
expect_refused "-p 53 override" "ports below 1024" -f -p 53 "$TMP/nouser.conf"

# a TCP port held by another process (without SO_REUSEPORT)
BUSY_PORT=$(free_port)
perl -MIO::Socket::INET -e '
    my $t = IO::Socket::INET->new(Proto=>"tcp", LocalAddr=>"127.0.0.1", LocalPort=>$ARGV[0], Listen=>1, ReuseAddr=>0) or exit 1;
    sleep 30' "$BUSY_PORT" &
HOLD=$!
PIDS="$PIDS $HOLD"
sleep 0.5
if kill -0 $HOLD 2>/dev/null; then
    write_conf "$TMP/busy.conf" "port $BUSY_PORT; user \"$RUN_USER\";"
    expect_refused "TCP port already in use" "cannot bind TCP port $BUSY_PORT" -f "$TMP/busy.conf"
else
    fail "could not hold TCP port $BUSY_PORT for the in-use check"
fi
kill -TERM $HOLD 2>/dev/null
wait $HOLD 2>/dev/null

write_conf "$TMP/varlog.conf" "port $PORT; user \"$RUN_USER\";" "
logging { channel q { file \"/var/log/karidns_nonroot_test/queries.log\"; }; category queries { q; }; };"
expect_refused "log file under /var/log" "Failed to open log file" -f "$TMP/varlog.conf"

write_conf "$TMP/defpid.conf" "port $PORT; user \"$RUN_USER\";"
expect_refused "default pid file (daemon mode)" "pid file" "$TMP/defpid.conf"

write_conf "$TMP/defctl.conf" "port $PORT; user \"$RUN_USER\";" "
control-channel { algorithm hmac-sha256; secret \"dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl\"; };"
expect_refused "default control socket path" "control socket" -f "$TMP/defctl.conf"

write_conf "$TMP/other.conf" "port $PORT; user \"$OTHER_USER\";"
expect_refused "user \"$OTHER_USER\" (another user)" "cannot switch" -f "$TMP/other.conf"

write_conf "$TMP/nouserx.conf" "port $PORT; user \"no_such_user_karidns\";"
expect_refused "unknown user" "not found" -f "$TMP/nouserx.conf"

# -----------------------------------------------------------------------------
if [ "$(id -u)" -eq 0 ]; then
    echo "[4] as root: an unopenable log file also refuses startup"
    write_conf "$TMP/rootlog.conf" "port $PORT; user \"nobody\";" "
logging { channel q { file \"$TMP/not_a_dir/queries.log\"; }; category queries { q; }; };"
    out="$TMP/rootlog.out"
    "$KARIDNS" -f "$TMP/rootlog.conf" > "$out" 2>&1 &
    p=$!
    PIDS="$PIDS $p"
    i=0; while kill -0 $p 2>/dev/null && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
    if kill -0 $p 2>/dev/null; then
        fail "root: karidns kept running with an unopenable log file"
    else
        wait $p; rc=$?
        if [ $rc -ne 0 ] && grep -q "Failed to open log file" "$out"; then
            ok "root: unopenable log file refused (exit $rc)"
        else
            fail "root: unopenable log file not refused (exit $rc)"; sed 's/^/      /' "$out"
        fi
    fi
fi

echo ""
echo "passed: $PASS, failed: $FAILS"
if [ $FAILS -ne 0 ]; then
    echo "[FAIL] non-root startup test"
    exit 1
fi
echo "[PASS] non-root startup test"
exit 0

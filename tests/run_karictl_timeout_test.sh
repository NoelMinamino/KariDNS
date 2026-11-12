#!/bin/sh
# ==============================================================================
# run_karictl_timeout_test.sh
#
# 0.6.2: karictl waits at most -t seconds (default 60, as rndc -t) for each part of the server's reply.  It used to wait for ever on a
# server that accepted the connection and never answered (the fault-injection sweep of PR #175 hung on it).
#  1. A listener that accepts and never sends the challenge: karictl -t 2 fails within a few seconds, with the message
#  2. The same after the challenge (the reply to the command never comes)
#  3. -t outside 1..86400, or not a number: usage error (exit 2) without connecting
# Needs perl (IO::Socket::UNIX) for the silent listener; SKIP without it.
# ==============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KARICTL="${KARICTL:-$ROOT_DIR/karictl}"
[ -x "$KARICTL" ] || make -C "$ROOT_DIR" karictl >/dev/null 2>&1 || { echo "FAIL: cannot build karictl"; exit 1; }
perl -MIO::Socket::UNIX -e 1 2>/dev/null || { echo "SKIP: perl with IO::Socket::UNIX is not available"; exit 0; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/karictl_timeout.XXXXXX")"
LPID=""
cleanup() { [ -n "$LPID" ] && kill "$LPID" 2>/dev/null; rm -rf "$TMP"; }
trap cleanup EXIT INT TERM
PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }

SOCK="$TMP/ctl.sock"
cat > "$TMP/karictl.conf" <<EOF
socket "$SOCK";
key "karictl" { algorithm hmac-sha256; secret "dGVzdC1vbmx5LWR1bW15LWtleS1kby1ub3QtdXNl"; };
EOF
chmod 600 "$TMP/karictl.conf"

# listen MODE: "silent" accepts and sends nothing; "challenge" sends a challenge, reads the answer and then sends nothing
listen() {
    rm -f "$SOCK"
    perl -MIO::Socket::UNIX -e '
        my ($path, $mode) = @ARGV;
        my $s = IO::Socket::UNIX->new(Type => SOCK_STREAM(), Local => $path, Listen => 5) or die "listen: $!";
        while (my $c = $s->accept) {
            if ($mode eq "challenge") { print $c "CHALLENGE " . ("a" x 64) . "\n"; $c->flush; my $l = <$c>; }
            sleep 30;
            close $c;
        }' "$SOCK" "$1" &
    LPID=$!
    i=0; while [ ! -S "$SOCK" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
}

# run_case LABEL: karictl -t 2 status must fail within 10 s and say why
run_case() {
    t0=$(date +%s)
    out=$("$KARICTL" -c "$TMP/karictl.conf" -t 2 status 2>&1); rc=$?
    dt=$(( $(date +%s) - t0 ))
    if [ "$rc" -ne 0 ] && [ "$dt" -le 10 ] && printf '%s\n' "$out" | grep -q "no reply from the server within 2 s"; then
        pass "$1: failed after $dt s (exit $rc)"
    else
        fail "$1: exit $rc after $dt s: $out"
    fi
    kill "$LPID" 2>/dev/null; wait "$LPID" 2>/dev/null; LPID=""
}

echo "=== karictl reply timeout (-t) ==="
listen silent
run_case "no challenge"
listen challenge
run_case "no reply to the command"

for bad in 0 86401 abc 5s ""; do
    out=$("$KARICTL" -c "$TMP/karictl.conf" -t "$bad" status 2>&1); rc=$?
    if [ "$rc" -eq 2 ] && printf '%s\n' "$out" | grep -q "is not a number of seconds"; then pass "-t '$bad' is refused"; else fail "-t '$bad': exit $rc: $out"; fi
done
out=$("$KARICTL" --help 2>&1)
printf '%s\n' "$out" | grep -q -- "-t seconds" && pass "--help lists -t" || fail "--help does not list -t"

echo "=== run_karictl_timeout_test: $PASS passed, $FAILS failed ==="
[ "$FAILS" -eq 0 ]

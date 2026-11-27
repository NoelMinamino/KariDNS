#!/bin/sh
# karicheck run as root (tools review 2026-11-23, T4-L4): `karicheck zone <domain> <file>` reads the file as root and parses it as
# `nobody` (or the -u user), so an $INCLUDE only root may read is refused and one anyone may read is taken; `-u root` keeps root.
# The file itself may be root's alone (it is read before the drop), standard input too.  -u for a user that does not exist is a usage
# error (exit 2); `-u nobody conf` drops before the configuration is read (a configuration only root may read is then an error).
# SKIP unless root and a user nobody.  No real names (.test).
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR/.." || exit 1
[ -x ./karicheck ] || { echo "SKIP: no ./karicheck"; exit 0; }
[ "$(id -u)" = "0" ] || { echo "SKIP: not root"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }
W=$(mktemp -d "${TMPDIR:-/tmp}/kc_root.XXXXXX")
trap 'rm -rf "$W"' EXIT INT TERM
chmod 755 "$W"
FAILED=0
fail() { echo "FAIL: $*"; FAILED=1; }

cat > "$W/z.zone" <<'EOF'
$TTL 300
$ORIGIN example.test.
@ IN SOA ns1.example.test. hostmaster.example.test. ( 1 3600 600 86400 60 )
@ IN NS ns1.example.test.
ns1 IN A 192.0.2.1
EOF
chmod 600 "$W/z.zone"                       # root's alone: read before the drop
printf 'www IN A 192.0.2.2\n' > "$W/secret.inc"
chmod 600 "$W/secret.inc"                   # root's alone: opened after the drop
printf 'web IN A 192.0.2.3\n' > "$W/open.inc"
chmod 644 "$W/open.inc"
{ cat "$W/z.zone"; printf '$INCLUDE %s/secret.inc\n' "$W"; } > "$W/zs.zone"
{ cat "$W/z.zone"; printf '$INCLUDE %s/open.inc\n' "$W"; } > "$W/zo.zone"
chmod 600 "$W/zs.zone" "$W/zo.zone"

# 1. a zone file only root may read is checked (read as root), and the verdict is the same as before
./karicheck zone example.test "$W/z.zone" > "$W/1.out" 2>&1 || fail "root-only zone file: exit $?: $(cat "$W/1.out")"
# 2. an $INCLUDE only root may read is opened as nobody: refused
if ./karicheck zone example.test "$W/zs.zone" > "$W/2.out" 2>&1; then fail "a root-only \$INCLUDE was read: the parser ran as root: $(cat "$W/2.out")"; fi
grep -qi "secret.inc" "$W/2.out" || fail "the refusal does not name the include: $(cat "$W/2.out")"
# 3. an \$INCLUDE anyone may read is taken
./karicheck zone example.test "$W/zo.zone" > "$W/3.out" 2>&1 || fail "a readable \$INCLUDE: exit $?: $(cat "$W/3.out")"
# 4. -u root keeps root: the root-only include is read
./karicheck -u root zone example.test "$W/zs.zone" > "$W/4.out" 2>&1 || fail "-u root: exit $?: $(cat "$W/4.out")"
# 5. standard input is read before the drop
./karicheck zone example.test - < "$W/z.zone" > "$W/5.out" 2>&1 || fail "standard input: exit $?: $(cat "$W/5.out")"
# 6. -u for a user that does not exist: a usage error
./karicheck -u no-such-user-kc zone example.test "$W/z.zone" > "$W/6.out" 2>&1; rc=$?
[ "$rc" -eq 2 ] || fail "-u no-such-user: exit $rc (want 2): $(cat "$W/6.out")"
# 7. --json -u: the document names the command, and the drop holds
./karicheck --json -u nobody zone example.test "$W/zs.zone" > "$W/7.out" 2>/dev/null; rc=$?
[ "$rc" -eq 1 ] || fail "--json -u nobody with a root-only include: exit $rc (want 1)"
grep -q '"command": *"zone"' "$W/7.out" || fail "--json -u: the document does not name the command: $(head -c 300 "$W/7.out")"
# 8. -u nobody conf: the configuration is read as nobody (one only root may read is an error), without -u as root
printf 'options { directory "%s"; };\n' "$W" > "$W/k.conf"
chmod 600 "$W/k.conf"
./karicheck conf "$W/k.conf" > "$W/8a.out" 2>&1 || fail "conf as root: exit $?: $(cat "$W/8a.out")"
if ./karicheck -u nobody conf "$W/k.conf" > "$W/8b.out" 2>&1; then fail "-u nobody conf read a root-only configuration: $(cat "$W/8b.out")"; fi

[ "$FAILED" -eq 0 ] || exit 1
echo "PASS: karicheck as root parses a zone file as nobody (-u user, -u root)"
exit 0

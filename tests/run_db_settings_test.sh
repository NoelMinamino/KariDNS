#!/bin/sh
# run_db_settings_test.sh - settings of database zones: domainmetadata and profiles -> restricted parse -> ACLs bounded by
# acl-ceiling, transfer-acl-match / update-acl-match (D14), profiles, metadata-only edits, configuration reload
# (beta design 1.3, 3.5, 3.7, 4.2, 7.1; milestone B7a).
#
# karidns with options { database { acl-ceiling { 127.0.0.1; 127.0.0.2; key "xfr"; }; } } and a SQLite3 database made with
# tests/db/zone2sql PLUS db/karidns_ext.sqlite3.sql; the loader runs as "nobody".  Clients come from 127.0.0.1, 127.0.0.2 and
# 127.0.0.3 (dag -b; loopback aliases are added when missing and removed at the end).  Checked:
#   - metadata ACLs: ALLOW-AXFR-FROM / TSIG-ALLOW-AXFR (PowerDNS: address OR key = transfer-acl-match any) and
#     ALLOW-DNSUPDATE-FROM / TSIG-ALLOW-DNSUPDATE (address AND key = update-acl-match all) allow and refuse the right
#     clients for AXFR and UPDATE; a zone without metadata refuses both;
#   - the ceiling: a client the database allows but the ceiling does not is refused, unless the request is signed with a key
#     the ceiling names; entries outside the ceiling are named in dbstatus; with no ceiling every database ACL refuses;
#   - a TSIG key that karidns.conf does not define: the zone is rejected (last good version and its settings kept), and when
#     the key goes away at a configuration reload the ACL that names it refuses everybody and dbstatus says so;
#   - profiles: a zone takes the statements of its profile, its own metadata replaces them statement by statement; an unknown
#     profile fails the zone in the loader; profile text with `include`, `file`, `type`, or an unclosed brace is refused by the
#     Backend; editing a profile re-sends the zones that use it (the change log), a metadata-only edit that keeps the serial is
#     applied (digest), identical settings are shared (dbstatus);
#   - acl-ceiling-match all (B7b): the client must be inside the ceiling by its address AND its key; any (the default) = either; a
#     ceiling with one kind of entry: that kind alone decides;
#   - karidns.conf zones keep "address AND key" for transfers and "address OR key" for updates unless transfer-acl-match /
#     update-acl-match say otherwise (the options work in karidns.conf too).
#
# Needs root.  SKIP otherwise, and when karidns, dag, karictl, karicheck, karidns-dbloader (SQLite3 driver), zone2sql or the
# sqlite3 CLI is missing.  KARIDNS=./karidns-asan runs it on the ASan build.
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the loader runs as another user)"; exit 0; fi
KARIDNS=${KARIDNS:-./karidns}
for b in "$KARIDNS" ./dag ./karictl ./karicheck ./karidns-dbloader ./tests/db/zone2sql; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
./karidns-dbloader --drivers | grep -qx sqlite3 || { echo "SKIP: karidns-dbloader has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_dbset.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
ADDED_ALIASES=""
cleanup() {
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    # wait for the manager (it stops its children first; a sanitizer build is slow): a KILL too early orphans them
    i=0; while [ -n "$SRV" ] && [ $i -lt 100 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    [ -n "$SRV" ] && kill -KILL "$SRV" 2>/dev/null
    for ip in $ADDED_ALIASES; do ifconfig lo0 inet "$ip" -alias 2>/dev/null || ifconfig lo inet "$ip" -alias 2>/dev/null; done
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
DAG="./dag @127.0.0.1 -p $PORT"
S_CTL="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"
S_XFR="eGZyLXNlY3JldC0wMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc="
S_UPD="dXBkLXNlY3JldC0wMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc="
S_OTH="b3RoLXNlY3JldC0wMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc="

# loopback aliases for the client addresses
for ip in 127.0.0.2 127.0.0.3; do
    if ! ifconfig lo0 2>/dev/null | grep -q "inet $ip "; then
        if ifconfig lo0 inet "$ip/32" alias 2>/dev/null || ifconfig lo inet "$ip/32" alias 2>/dev/null; then
            ADDED_ALIASES="$ADDED_ALIASES $ip"
        else
            echo "SKIP: cannot add the loopback alias $ip"; exit 0
        fi
    fi
done

# ---------------------------------------------------------------- fixtures
mkdir "$T/db" "$T/z"
mkzone() {   # mkzone NAME SERIAL
    cat > "$T/z/$1.zone" <<EOF
\$ORIGIN $1.
\$TTL 300
@ SOA ns1.$1. host.$1. $2 3600 600 86400 300
@ NS ns1
ns1 A 192.0.2.1
www A 192.0.2.10
EOF
}
DBZONES="meta addr nokey noacl prof prof2 unkprof evil evil2 evil3 chg edit"
for z in $DBZONES; do mkzone "$z.test" 10; done
cat > "$T/file.zone" <<'EOF'
$TTL 300
@ SOA ns host 1 2 3 4 5
@ NS ns
ns A 192.0.2.1
www A 192.0.2.80
EOF
sqlite3 "$T/db/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
sqlite3 "$T/db/z.db" < db/karidns_ext.sqlite3.sql
for z in $DBZONES; do ./tests/db/zone2sql --dialect sqlite3 "$T/z/$z.test.zone" 2>/dev/null | sqlite3 "$T/db/z.db"; done
sq() { sqlite3 "$T/db/z.db" "$@"; }
meta() {   # meta ZONE KIND CONTENT
    sq "INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, '$2', '$3' FROM domains WHERE name = '$1.test'"
}
# metadata ACLs (PowerDNS names): AXFR from 127.0.0.1 or signed with xfr; UPDATE from 127.0.0.1 AND signed with upd
meta meta ALLOW-AXFR-FROM 127.0.0.1
meta meta TSIG-ALLOW-AXFR xfr
meta meta ALLOW-DNSUPDATE-FROM 127.0.0.1
meta meta TSIG-ALLOW-DNSUPDATE upd
# addresses: 127.0.0.2 (inside the ceiling), 127.0.0.3 and 198.51.100.0/24 (outside it)
meta addr ALLOW-AXFR-FROM 127.0.0.2
meta addr ALLOW-AXFR-FROM 127.0.0.3
meta addr ALLOW-AXFR-FROM 198.51.100.0/24
# a key that karidns.conf does not define
meta nokey TSIG-ALLOW-AXFR ghost
# profiles
sq "INSERT INTO karidns_profiles (name, settings) VALUES ('gold', 'allow-transfer { 127.0.0.1; }; ixfr-history 2; # the usual ACL')"
sq "INSERT INTO karidns_profiles (name, settings) VALUES ('evil', 'include \"/etc/passwd\"; allow-transfer { any; };')"
sq "INSERT INTO karidns_profiles (name, settings) VALUES ('evil2', 'file \"/tmp/x\"; type slave;')"
sq "INSERT INTO karidns_profiles (name, settings) VALUES ('evil3', 'allow-transfer { 127.0.0.1;')"
meta prof X-KARIDNS-PROFILE gold
meta prof2 X-KARIDNS-PROFILE gold
meta prof2 ALLOW-AXFR-FROM 127.0.0.2          # the zone's own statement replaces the profile's allow-transfer
meta unkprof X-KARIDNS-PROFILE nosuch
meta evil X-KARIDNS-PROFILE evil
meta evil2 X-KARIDNS-PROFILE evil2
meta evil3 X-KARIDNS-PROFILE evil3
meta evil3 ALLOW-AXFR-FROM 127.0.0.2
# zones that are edited later
meta chg TSIG-ALLOW-AXFR xfr
meta edit ALLOW-AXFR-FROM 127.0.0.1
NZ=$(sq "SELECT count(*) FROM domains")
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
install -o root -g wheel -m 755 ./karidns-dbloader "$T/karidns-dbloader" 2>/dev/null || { cp ./karidns-dbloader "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$S_CTL"; };
EOF
chmod 600 "$T/karictl.conf"
KCTL="./karictl -c $T/karictl.conf"

# conf FILE VARIANT: full = keys xfr, upd and the ceiling; nokey = no key xfr (and no key in the ceiling); noceil = no ceiling;
# ceilall / ceilany / ceilalladdr = acl-ceiling-match all / any / all with addresses only (B7b)
conf() {
    v=${2:-full}
    {
        [ "$v" != nokey ] && printf 'key "xfr" { algorithm hmac-sha256; secret "%s"; };\n' "$S_XFR"
        printf 'key "upd" { algorithm hmac-sha256; secret "%s"; };\n' "$S_UPD"
        printf 'key "oth" { algorithm hmac-sha256; secret "%s"; };\n' "$S_OTH"
        case "$v" in
        full) CEIL='acl-ceiling { 127.0.0.1; 127.0.0.2; key "xfr"; };' ;;
        nokey) CEIL='acl-ceiling { 127.0.0.1; 127.0.0.2; };' ;;
        noceil) CEIL='' ;;
        narrow) CEIL='acl-ceiling { 127.0.0.1; key "xfr"; };' ;;
        ceilall) CEIL='acl-ceiling { 127.0.0.1; 127.0.0.2; key "xfr"; }; acl-ceiling-match all;' ;;
        ceilany) CEIL='acl-ceiling { 127.0.0.1; 127.0.0.2; key "xfr"; }; acl-ceiling-match any;' ;;
        ceilalladdr) CEIL='acl-ceiling { 127.0.0.1; 127.0.0.2; }; acl-ceiling-match all;' ;;
        esac
        cat <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; db-reload-timeout 4; $CEIL };
};
control-channel { socket "$T/ctl.sock"; secret "$S_CTL"; };
zone "file.test" { type primary; file "$T/file.zone"; };
EOF
        if [ "$v" != nokey ]; then
        cat <<EOF
zone "fany.test" { type primary; file "$T/fany.zone"; allow-transfer { 127.0.0.1; key "xfr"; }; transfer-acl-match any;
                   allow-update { 127.0.0.1; key "upd"; }; update-acl-match all; };
zone "fdef.test" { type primary; file "$T/fdef.zone"; allow-transfer { 127.0.0.1; key "xfr"; }; allow-update { 127.0.0.1; key "upd"; }; };
zone "fall.test" { type primary; file "$T/fall.zone"; allow-transfer { 127.0.0.1; key "xfr"; }; transfer-acl-match all; };
EOF
        fi
    } > "$1"
}
for n in fany fdef fall; do mkzone "$n.test" 5; cp "$T/z/$n.test.zone" "$T/$n.zone"; done

wait_log() {   # wait_log LOG PATTERN SECONDS [COUNT]
    i=0; want=${4:-1}
    while [ $i -lt $(($3 * 10)) ]; do
        [ "$(grep -c -- "$2" "$1" 2>/dev/null)" -ge "$want" ] && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
dbst() { $KCTL dbstatus "$@" 2>&1; }

# xfr ZONE SRC [KEY:SECRET]: success (0) when the transfer returns the zone's data
xfr() {
    out=$($DAG -b "$2" "$1" AXFR +nohexdump ${3:+-y hmac-sha256:$3} 2>&1)
    printf '%s\n' "$out" | grep -q "^www\.$1\."
}
xfr_ok() {   # xfr_ok DESCRIPTION ZONE SRC [KEY:SECRET]
    d=$1; shift
    if xfr "$@"; then pass "$d"; else fail "$d (the transfer was refused)"; fi
}
xfr_no() {
    d=$1; shift
    if xfr "$@"; then fail "$d (the transfer was allowed)"; else pass "$d"; fi
}
# upd ZONE SRC [KEY:SECRET]: the RCODE of an UPDATE that adds x.ZONE
upd() {
    $DAG -b "$2" "$1" SOA +nohexdump ${3:+-y hmac-sha256:$3} --update-add "x.$1 300 IN A 192.0.2.99" 2>&1 | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1
}
upd_is() {   # upd_is DESCRIPTION WANT ZONE SRC [KEY:SECRET]
    d=$1; w=$2; shift 2
    got=$(upd "$@")
    [ "$got" = "$w" ] && pass "$d" || fail "$d (got '$got', want $w)"
}
ans() { $DAG "$@" +short +nohexdump 2>/dev/null; }

# ================================================================ start
echo "== startup"
conf "$T/k.conf" full
"$KARIDNS" -c "$T/k.conf" -f > "$T/srv.log" 2>&1 &
SRV=$!
if wait_log "$T/srv.log" "\[DB\] initial load complete" 20; then pass "the startup batch is complete"; else fail "no 'initial load complete' line"; sed 's/^/         /' "$T/srv.log" | tail -20; fi
wait_log "$T/srv.log" "Backend result for batch 1:" 15 && pass "batch 1 has its result" || fail "no result for batch 1"
./karicheck conf "$T/k.conf" > "$T/kc.out" 2>&1; RC=$?
[ $RC -eq 0 ] && pass "karicheck conf accepts transfer-acl-match / update-acl-match and the ceiling" || { fail "karicheck conf: rc $RC"; sed 's/^/         /' "$T/kc.out" | tail -5; }
grep -q "no acl-ceiling" "$T/kc.out" && fail "karicheck warns about a missing ceiling although one is set" || pass "karicheck: no 'no acl-ceiling' warning with a ceiling"
[ "$(ans www.meta.test A)" = "192.0.2.10" ] && pass "database zones answer" || fail "www.meta.test does not answer"
grep -q "warning:.*PowerDNS accepts either\|warning:.*dynamic update is disabled" "$T/srv.log" && fail "the closing warnings of B2 are still logged" || pass "no B2 'closing' warnings in the log"

# ================================================================ metadata ACLs
echo "== AXFR: ALLOW-AXFR-FROM or TSIG-ALLOW-AXFR (transfer-acl-match any)"
xfr_ok "meta.test: from 127.0.0.1 unsigned (address matches)" meta.test 127.0.0.1
xfr_ok "meta.test: from 127.0.0.3 signed with xfr (key matches; the ceiling names the key)" meta.test 127.0.0.3 "xfr:$S_XFR"
xfr_no "meta.test: from 127.0.0.2 unsigned (neither the address nor the key)" meta.test 127.0.0.2
xfr_no "meta.test: from 127.0.0.2 signed with another key" meta.test 127.0.0.2 "oth:$S_OTH"
xfr_no "meta.test: a bad signature" meta.test 127.0.0.1 "xfr:$S_OTH"
xfr_no "noacl.test (no metadata): refused for everybody" noacl.test 127.0.0.1
xfr_no "noacl.test: signed with xfr" noacl.test 127.0.0.1 "xfr:$S_XFR"

echo "== UPDATE: ALLOW-DNSUPDATE-FROM and TSIG-ALLOW-DNSUPDATE (update-acl-match all)"
upd_is "meta.test: address only is refused" REFUSED meta.test 127.0.0.1
upd_is "meta.test: key from another address is refused" REFUSED meta.test 127.0.0.2 "upd:$S_UPD"
upd_is "meta.test: another key from the right address is refused" REFUSED meta.test 127.0.0.1 "oth:$S_OTH"
upd_is "meta.test: the right address and the right key" NOERROR meta.test 127.0.0.1 "upd:$S_UPD"
[ "$(ans x.meta.test A)" = "192.0.2.99" ] && pass "the update is in the zone" || fail "the update is not in the zone"
upd_is "noacl.test: no allow-update" REFUSED noacl.test 127.0.0.1

echo "== karidns.conf zones keep their meaning, and the options work there"
xfr_ok "fdef.test (allow-transfer with an address and a key, no transfer-acl-match: BIND first match, address or key): the address alone" fdef.test 127.0.0.1
xfr_no "fall.test (transfer-acl-match all = address AND key, the meaning before the first-match order): the address alone" fall.test 127.0.0.1
xfr_ok "fall.test: address and key" fall.test 127.0.0.1 "xfr:$S_XFR"
xfr_no "fall.test: the key from another address" fall.test 127.0.0.3 "xfr:$S_XFR"
xfr_ok "fdef.test: address and key" fdef.test 127.0.0.1 "xfr:$S_XFR"
xfr_ok "fdef.test: the key from another address (first match: the key element)" fdef.test 127.0.0.3 "xfr:$S_XFR"
xfr_ok "fany.test (transfer-acl-match any): the address alone" fany.test 127.0.0.1
xfr_ok "fany.test: the key alone, from another address" fany.test 127.0.0.3 "xfr:$S_XFR"
xfr_no "fany.test: neither" fany.test 127.0.0.3
upd_is "fdef.test (allow-update address OR key): the address alone" NOERROR fdef.test 127.0.0.1
upd_is "fdef.test: the key alone" NOERROR fdef.test 127.0.0.3 "upd:$S_UPD"
upd_is "fdef.test: neither" REFUSED fdef.test 127.0.0.3
upd_is "fany.test (update-acl-match all): the address alone" REFUSED fany.test 127.0.0.1
upd_is "fany.test: address and key" NOERROR fany.test 127.0.0.1 "upd:$S_UPD"
upd_is "fany.test: the key from another address" REFUSED fany.test 127.0.0.3 "upd:$S_UPD"

# ================================================================ the ceiling
echo "== acl-ceiling"
xfr_ok "addr.test: 127.0.0.2 is in the database ACL and in the ceiling" addr.test 127.0.0.2
xfr_no "addr.test: 127.0.0.3 is in the database ACL but not in the ceiling" addr.test 127.0.0.3
xfr_ok "addr.test: 127.0.0.3 signed with xfr is inside the ceiling by its key" addr.test 127.0.0.3 "xfr:$S_XFR"
xfr_no "addr.test: 127.0.0.3 signed with a key the ceiling does not name" addr.test 127.0.0.3 "oth:$S_OTH"
xfr_no "addr.test: 127.0.0.1 is in the ceiling but not in the database ACL" addr.test 127.0.0.1
OUT=$(dbst addr.test)
printf '%s\n' "$OUT" | grep -q "acl-ceiling: .*allow-transfer 127.0.0.3 lies outside acl-ceiling.*allow-transfer 198.51.100.0/24 lies outside acl-ceiling" && pass "dbstatus addr.test names the entries the ceiling cuts away" || { fail "dbstatus addr.test"; printf '%s\n' "$OUT" | sed 's/^/         /'; }
OUT=$(dbst meta.test)
printf '%s\n' "$OUT" | grep -q "settings: the zone's own metadata" && printf '%s\n' "$OUT" | grep -q "allow-transfer: addresses 127.0.0.1 keys xfr (match any)" &&
    printf '%s\n' "$OUT" | grep -q "allow-update: entries 127.0.0.1, upd (match all)" && pass "dbstatus meta.test shows the settings and the match modes" || { fail "dbstatus meta.test"; printf '%s\n' "$OUT" | sed 's/^/         /'; }
dbst noacl.test | grep -q "settings: none" && pass "dbstatus noacl.test: no settings" || fail "dbstatus noacl.test"

# ================================================================ unknown key
echo "== a TSIG key that karidns.conf does not define"
OUT=$(dbst nokey.test)
printf '%s\n' "$OUT" | grep -q "status rejected (no version loaded), last error: the settings name the TSIG key 'ghost', which is not defined in karidns.conf" && pass "nokey.test is rejected: no version, the reason in dbstatus" || { fail "dbstatus nokey.test"; printf '%s\n' "$OUT" | sed 's/^/         /'; }
$DAG www.nokey.test A +nohexdump 2>/dev/null | grep -q "status: REFUSED" && pass "nokey.test is not served" || fail "nokey.test answers"
xfr_ok "chg.test (key xfr): transfer with the key" chg.test 127.0.0.3 "xfr:$S_XFR"
sq "UPDATE domainmetadata SET content = 'ghost' WHERE kind = 'TSIG-ALLOW-AXFR' AND domain_id = (SELECT id FROM domains WHERE name = 'chg.test')"
OUT=$($KCTL reload chg.test 2>&1); RC=$?
printf '%s\n' "$OUT" | grep -q "rejected: the settings name the TSIG key 'ghost'.*the last good version, if any, keeps serving" && [ $RC -eq 3 ] && pass "reload chg.test after naming an unknown key: $OUT" || fail "reload chg.test: rc $RC '$OUT'"
xfr_ok "chg.test keeps its last good settings: the key xfr still transfers" chg.test 127.0.0.3 "xfr:$S_XFR"
[ "$(ans www.chg.test A)" = "192.0.2.10" ] && pass "chg.test still answers (the last good version)" || fail "chg.test does not answer"
sq "UPDATE domainmetadata SET content = 'xfr' WHERE kind = 'TSIG-ALLOW-AXFR' AND domain_id = (SELECT id FROM domains WHERE name = 'chg.test')"
OUT=$($KCTL reload chg.test 2>&1)
printf '%s\n' "$OUT" | grep -q "applied, serial 10$" && pass "the corrected metadata is applied: $OUT" || fail "reload chg.test again: '$OUT'"

# ================================================================ metadata-only edit
echo "== a metadata-only edit that keeps the serial is applied"
xfr_ok "edit.test: 127.0.0.1 may transfer" edit.test 127.0.0.1
xfr_no "edit.test: 127.0.0.2 may not" edit.test 127.0.0.2
OUT=$($KCTL reload edit.test 2>&1)
printf '%s\n' "$OUT" | grep -q "unchanged, serial 10$" && pass "nothing changed: $OUT" || fail "reload edit.test (nothing changed): '$OUT'"
sq "UPDATE domainmetadata SET content = '127.0.0.2' WHERE kind = 'ALLOW-AXFR-FROM' AND domain_id = (SELECT id FROM domains WHERE name = 'edit.test')"
OUT=$($KCTL reload edit.test 2>&1)
printf '%s\n' "$OUT" | grep -q "applied, serial 10$" && pass "the digest covers the settings: $OUT" || fail "reload edit.test after the edit: '$OUT'"
xfr_ok "edit.test: 127.0.0.2 may transfer now" edit.test 127.0.0.2
xfr_no "edit.test: 127.0.0.1 may not any more" edit.test 127.0.0.1
sq "UPDATE domainmetadata SET content = '127.0.0.1' WHERE kind = 'ALLOW-AXFR-FROM' AND domain_id = (SELECT id FROM domains WHERE name = 'edit.test')"
$KCTL reload > /dev/null 2>&1                      # reload (all): found through the change log
i=0; while [ $i -lt 50 ]; do xfr edit.test 127.0.0.1 && break; sleep 0.2; i=$((i + 1)); done
xfr_ok "edit.test: back to 127.0.0.1 by reload (all)" edit.test 127.0.0.1

# ================================================================ profiles
echo "== profiles"
xfr_ok "prof.test: the profile's allow-transfer admits 127.0.0.1" prof.test 127.0.0.1
xfr_no "prof.test: not 127.0.0.2" prof.test 127.0.0.2
xfr_ok "prof2.test: its own ALLOW-AXFR-FROM replaces the profile's allow-transfer" prof2.test 127.0.0.2
xfr_no "prof2.test: and 127.0.0.1 is no longer allowed" prof2.test 127.0.0.1
OUT=$(dbst prof.test)
printf '%s\n' "$OUT" | grep -q "settings: profile 'gold'" && pass "dbstatus prof.test names the profile" || { fail "dbstatus prof.test"; printf '%s\n' "$OUT" | sed 's/^/         /'; }
OUT=$(dbst)
printf '%s\n' "$OUT" | grep -q "^settings: [0-9][0-9]* distinct" && pass "dbstatus counts the distinct settings: $(printf '%s\n' "$OUT" | grep '^settings:')" || { fail "dbstatus summary"; printf '%s\n' "$OUT" | sed 's/^/         /'; }
OUT=$(dbst unkprof.test)
printf '%s\n' "$OUT" | grep -q "last error: the profile 'nosuch' (X-KARIDNS-PROFILE) is not defined in karidns_profiles" && pass "an unknown profile fails the zone in the loader" || { fail "dbstatus unkprof.test"; printf '%s\n' "$OUT" | sed 's/^/         /'; }
dbst evil.test | grep -q "last error: profile text: 'include' is not allowed in the settings of a database zone" && pass "profile text with include is refused by the Backend" || { fail "evil.test"; dbst evil.test | sed 's/^/         /'; }
dbst evil2.test | grep -q "last error: profile text: statement 'file' is not allowed in the settings of a database zone" && pass "profile text with file / type is refused" || { fail "evil2.test"; dbst evil2.test | sed 's/^/         /'; }
dbst evil3.test | grep -q "last error: profile text: " && pass "a profile that leaves a block open is refused on its own (it cannot swallow the zone's statements)" || { fail "evil3.test"; dbst evil3.test | sed 's/^/         /'; }
for z in evil evil2 evil3 unkprof; do
    $DAG www.$z.test A +nohexdump 2>/dev/null | grep -q "status: REFUSED" && pass "$z.test is not served" || fail "$z.test is served"
done
[ -r /etc/passwd ] && ! grep -q "passwd" "$T/srv.log" && pass "the Backend never tried to read the included file" || fail "the log mentions the included file"

sq "UPDATE karidns_profiles SET settings = 'allow-transfer { 127.0.0.2; };' WHERE name = 'gold'"
OUT=$($KCTL reload prof.test 2>&1)
printf '%s\n' "$OUT" | grep -q "applied, serial 10$" && pass "editing the profile makes the zone new (digest covers the profile text): $OUT" || fail "reload prof.test after the profile edit: '$OUT'"
xfr_ok "prof.test: the edited profile admits 127.0.0.2" prof.test 127.0.0.2
xfr_no "prof.test: and not 127.0.0.1" prof.test 127.0.0.1
sq "UPDATE karidns_profiles SET settings = 'allow-transfer { 127.0.0.1; };' WHERE name = 'gold'"
sq "SELECT count(*) FROM karidns_changes" > /dev/null
$KCTL reload > /dev/null 2>&1                      # reload (all): the trigger on karidns_profiles logged both zones
i=0; while [ $i -lt 50 ]; do xfr prof.test 127.0.0.1 && break; sleep 0.2; i=$((i + 1)); done
xfr_ok "prof.test: back to 127.0.0.1 by reload (all) (the trigger on karidns_profiles logged the zone)" prof.test 127.0.0.1
xfr_no "prof2.test: still its own ACL" prof2.test 127.0.0.1

# ================================================================ configuration reload
echo "== configuration reload: a key goes away, the ceiling shrinks"
xfr_ok "meta.test before: from 127.0.0.1" meta.test 127.0.0.1
xfr_ok "addr.test before: from 127.0.0.2" addr.test 127.0.0.2
conf "$T/k.conf" nokey
OUT=$($KCTL reconfig 2>&1)
printf '%s\n' "$OUT" | grep -q "^OK" && pass "reconfig without the key xfr: $OUT" || fail "reconfig: '$OUT'"
wait_log "$T/srv.log" "naming a TSIG key that is not defined" 10 && pass "log: the settings were checked against the new configuration" || fail "no reload log line"
xfr_no "meta.test names the key xfr, which is gone: the ACL refuses even the listed address" meta.test 127.0.0.1
OUT=$(dbst meta.test)
printf '%s\n' "$OUT" | grep -q "settings error: the TSIG key 'xfr' is not defined in karidns.conf" && pass "dbstatus meta.test: settings error names the key" || { fail "dbstatus meta.test after the key went"; printf '%s\n' "$OUT" | sed 's/^/         /'; }
dbst | grep -q "^settings: .* [1-9][0-9]* zone(s) name a TSIG key that karidns.conf does not define" && pass "dbstatus summary counts them" || fail "dbstatus summary after the key went"
xfr_ok "addr.test (no key in its ACL) is not affected" addr.test 127.0.0.2
conf "$T/k.conf" full
OUT=$($KCTL reconfig 2>&1)
printf '%s\n' "$OUT" | grep -q "^OK" && pass "reconfig with the key back: $OUT" || fail "reconfig: '$OUT'"
xfr_ok "meta.test works again once the key is back" meta.test 127.0.0.1
conf "$T/k.conf" narrow
$KCTL reconfig > /dev/null 2>&1
xfr_no "addr.test: 127.0.0.2 left the ceiling" addr.test 127.0.0.2
xfr_ok "addr.test: signed with xfr it is still inside" addr.test 127.0.0.2 "xfr:$S_XFR"
dbst addr.test | grep -q "allow-transfer 127.0.0.2 lies outside acl-ceiling" && pass "dbstatus names the entry that left the ceiling" || { fail "dbstatus addr.test after the ceiling shrank"; dbst addr.test | sed 's/^/         /'; }
echo "== SIGHUP re-checks the settings too"
HN=$(grep -c "with ACLs, [1-9][0-9]* naming a TSIG key" "$T/srv.log")
conf "$T/k.conf" nokey
kill -HUP "$SRV"
wait_log "$T/srv.log" "with ACLs, [1-9][0-9]* naming a TSIG key" 10 $((HN + 1)) && pass "SIGHUP: the settings were checked against the new configuration" || fail "SIGHUP: no re-check line"
xfr_no "SIGHUP: meta.test refuses while the key xfr is gone" meta.test 127.0.0.1
conf "$T/k.conf" full
HZ=$(grep -c "with ACLs, 0 naming a TSIG key" "$T/srv.log")
kill -HUP "$SRV"
wait_log "$T/srv.log" "with ACLs, 0 naming a TSIG key" 10 $((HZ + 1)) && pass "SIGHUP with the key back: nothing names an undefined key" || fail "SIGHUP: no clean re-check line"
xfr_ok "SIGHUP: meta.test works again" meta.test 127.0.0.1
conf "$T/k.conf" narrow
$KCTL reconfig > /dev/null 2>&1
echo "== no acl-ceiling at all"
conf "$T/k.conf" noceil
$KCTL reconfig > /dev/null 2>&1
xfr_no "addr.test: no ceiling, the database ACL refuses 127.0.0.2" addr.test 127.0.0.2
xfr_no "meta.test: no ceiling, refused for the listed address" meta.test 127.0.0.1
xfr_no "meta.test: and for the key" meta.test 127.0.0.1 "xfr:$S_XFR"
upd_is "meta.test: no ceiling, no update either" REFUSED meta.test 127.0.0.1 "upd:$S_UPD"
dbst addr.test | grep -q "acl-ceiling: no acl-ceiling is configured: these ACLs refuse everybody" && pass "dbstatus says why" || fail "dbstatus without a ceiling"
grep -q "options { database { acl-ceiling } } is not configured" "$T/srv.log" && pass "the log says so" || fail "no log line about the missing ceiling"
./karicheck conf "$T/k.conf" > "$T/kc.out" 2>&1
grep -q "database: no acl-ceiling; the ACLs of database zones" "$T/kc.out" && pass "karicheck conf warns about a missing ceiling" || { fail "karicheck conf: no warning"; sed 's/^/         /' "$T/kc.out" | tail -5; }
xfr_ok "file zones are not bounded by the ceiling: fdef.test" fdef.test 127.0.0.1 "xfr:$S_XFR"
conf "$T/k.conf" full
$KCTL reconfig > /dev/null 2>&1
xfr_ok "addr.test: the ceiling is back" addr.test 127.0.0.2

# ================================================================ acl-ceiling-match (B7b)
echo "== acl-ceiling-match all: the client must be inside the ceiling by its address AND by its key"
conf "$T/k.conf" ceilall
OUT=$($KCTL reconfig 2>&1)
printf '%s\n' "$OUT" | grep -q "^OK" && pass "reconfig with acl-ceiling-match all: $OUT" || fail "reconfig: '$OUT'"
./karicheck conf "$T/k.conf" > "$T/kc.out" 2>&1; RC=$?
[ $RC -eq 0 ] && ! grep -q "acl-ceiling-match" "$T/kc.out" && pass "karicheck conf accepts acl-ceiling-match all with addresses and keys, without a warning" || { fail "karicheck conf (ceilall): rc $RC"; sed 's/^/         /' "$T/kc.out" | tail -4; }
xfr_no "addr.test: 127.0.0.2 is in the database ACL and in the ceiling by address, but not signed" addr.test 127.0.0.2
xfr_ok "addr.test: 127.0.0.2 signed with xfr (address and key are both inside)" addr.test 127.0.0.2 "xfr:$S_XFR"
xfr_no "addr.test: 127.0.0.3 signed with xfr (the key is inside, the address is not)" addr.test 127.0.0.3 "xfr:$S_XFR"
xfr_no "addr.test: 127.0.0.2 signed with a key the ceiling does not name" addr.test 127.0.0.2 "oth:$S_OTH"
xfr_no "meta.test: 127.0.0.1 unsigned (database ACL: address or key; the ceiling needs both)" meta.test 127.0.0.1
xfr_ok "meta.test: 127.0.0.1 signed with xfr" meta.test 127.0.0.1 "xfr:$S_XFR"
xfr_no "meta.test: 127.0.0.3 signed with xfr (the database ACL allows the key, the ceiling does not allow the address)" meta.test 127.0.0.3 "xfr:$S_XFR"
upd_is "meta.test: the update ACL (address AND upd) is bounded by the ceiling too; upd is not a ceiling key" REFUSED meta.test 127.0.0.1 "upd:$S_UPD"
xfr_ok "fdef.test: file zones are not bounded by the ceiling" fdef.test 127.0.0.1 "xfr:$S_XFR"
echo "== acl-ceiling-match any (the default, B7a): address OR key"
conf "$T/k.conf" ceilany
$KCTL reconfig > /dev/null 2>&1
xfr_ok "addr.test: 127.0.0.2 unsigned" addr.test 127.0.0.2
xfr_ok "addr.test: 127.0.0.3 signed with xfr" addr.test 127.0.0.3 "xfr:$S_XFR"
xfr_no "addr.test: 127.0.0.3 unsigned" addr.test 127.0.0.3
xfr_ok "meta.test: 127.0.0.1 unsigned" meta.test 127.0.0.1
echo "== acl-ceiling-match all with only addresses in the ceiling: that kind alone decides"
conf "$T/k.conf" ceilalladdr
$KCTL reconfig > /dev/null 2>&1
xfr_ok "addr.test: 127.0.0.2 unsigned" addr.test 127.0.0.2
xfr_no "addr.test: 127.0.0.3 signed with xfr (no key is listed in the ceiling)" addr.test 127.0.0.3 "xfr:$S_XFR"
./karicheck conf "$T/k.conf" > "$T/kc.out" 2>&1
grep -q "acl-ceiling-match all has no effect: acl-ceiling lists only addresses" "$T/kc.out" && pass "karicheck conf warns that all has no effect with one kind of entry" || { fail "karicheck conf (ceilalladdr)"; sed 's/^/         /' "$T/kc.out" | tail -4; }
printf 'options { database { driver sqlite3; database-file "%s/db/z.db"; acl-ceiling-match both; }; };\n' "$T" > "$T/bad.conf"
./karicheck conf "$T/bad.conf" > "$T/bad.out" 2>&1; RC=$?
[ $RC -ne 0 ] && grep -q "any or all" "$T/bad.out" && pass "karicheck conf refuses acl-ceiling-match both (any or all)" || { fail "karicheck conf bad.conf (ceiling): rc $RC"; sed 's/^/         /' "$T/bad.out" | tail -4; }
conf "$T/k.conf" full
$KCTL reconfig > /dev/null 2>&1
xfr_ok "addr.test: back to the default, 127.0.0.2 unsigned" addr.test 127.0.0.2

# ================================================================ karicheck conf with the new options
echo "== karicheck conf: the options"
cat > "$T/m.conf" <<EOF
key "k1" { algorithm hmac-sha256; secret "$S_XFR"; };
zone "a.test" { type primary; file "$T/file.zone"; allow-transfer { 127.0.0.1; key "k1"; }; transfer-acl-match any; allow-update { 127.0.0.1; key "k1"; }; update-acl-match all; };
zone "b.test" { type primary; file "$T/file.zone"; allow-transfer { 127.0.0.1; }; transfer-acl-match any; update-acl-match all; };
EOF
OUT=$(./karicheck conf "$T/m.conf" 2>&1); RC=$?
[ $RC -eq 0 ] && pass "karicheck conf accepts the options" || { fail "karicheck conf m.conf: rc $RC"; printf '%s\n' "$OUT" | sed 's/^/         /' | tail -5; }
printf '%s\n' "$OUT" | grep -q "Zone 'b.test.': transfer-acl-match has no effect: allow-transfer lists only addresses" && pass "karicheck warns when the option has nothing to choose between" || { fail "karicheck lint (transfer)"; printf '%s\n' "$OUT" | sed 's/^/         /' | tail -6; }
printf '%s\n' "$OUT" | grep -q "Zone 'b.test.': update-acl-match has no effect without allow-update" && pass "karicheck warns about update-acl-match without allow-update" || fail "karicheck lint (update)"
printf '%s\n' "$OUT" | grep -q "Zone 'a.test.'.*acl-match" && fail "karicheck warns about a zone that uses both kinds of entry" || pass "no warning for a zone with addresses and keys"
printf 'zone "a.test" { type primary; file "x"; transfer-acl-match both; };\n' > "$T/bad.conf"
./karicheck conf "$T/bad.conf" > "$T/bad.out" 2>&1; RC=$?
[ $RC -ne 0 ] && grep -q "any or all" "$T/bad.out" && pass "karicheck conf refuses transfer-acl-match both (any or all)" || { fail "karicheck conf bad.conf: rc $RC"; sed 's/^/         /' "$T/bad.out" | tail -4; }

# ================================================================ stop
echo "== SIGTERM"
kill -TERM "$SRV"
i=0; while [ $i -lt 100 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
if kill -0 "$SRV" 2>/dev/null; then fail "karidns did not stop within 10 s"; else pass "karidns stopped"; fi
sleep 0.5
LEFT=$(pgrep -f "karidns.*$T" | tr '\n' ' ')
[ -z "$LEFT" ] && pass "no process of this server is left" || fail "left over: $LEFT"

echo "== $PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ]

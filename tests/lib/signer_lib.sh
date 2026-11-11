# tests/lib/signer_lib.sh - shared by tests/run_signer_test.sh (SQLite3) and tests/run_signer_pg_test.sh (PostgreSQL): sourced, not run.
#
# The scenarios of karidns-signer (0.6.0 item C, planning 3.11) are the same on both databases; a test script sets the database up, defines the
# hooks below, and calls the sg_phase_* functions it wants.  Everything is plain sh (FreeBSD has no bash).
#
# Variables the script sets:
#   ROOT T            the source tree, the temporary directory (mode 0755); the signer's work-dir is $T/work (0700, owned by the signer's user)
#   PASS FAILS        counters; pass / fail DESCRIPTION are defined here
#   SG_CONF SG_LOG    the signer's configuration file (the script writes it with sg_write_conf) and log
#   ZDB               the database words of karidns-zone as the owner: "--no-config --sqlite3 FILE" or "--no-config --conninfo-file FILE"
#   SG_SIGNED_AT      SQL for karidns_signer_state.signed_at as unix seconds;   SG_DUE0   SQL for "next_due = the beginning of time"
#   SG_SERVER         1 when a karidns server serves the database (root only); then qa_dnssec NAME TYPE and sg_server_reload exist
# Functions the script defines:
#   dbq SQL           run SQL as the owner of the database, print the result (one value per line, no headers)
#   asu CMD ARGS...   run a command as the user the signer runs as (the PostgreSQL user when the test is root; else ourselves)
# What this file provides is prefixed sg_.

NODE=${NODE:-node}
SG_BT="$T/bt"                      # BIND's tools, with a dnssec-signzone that can be slowed down (a file $T/out/slow, see sg_slow)
SG_PIDFILE="$T/out/sg.pid"           # (in out: the signer writes it, as the PostgreSQL user when the test is root)
SG_PID=""
SG_SHELL=""
SG_RC=0

pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -12 | sed 's/^/         /'; }
sg_eq() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (got '$2', wanted '$3')"; fi; }
sg_has() { if printf '%s\n' "$2" | grep -q -- "$3"; then pass "$1"; else fail "$1 (no '$3' in: $(printf '%s' "$2" | head -c 300))"; fi; }
sg_hasnt() { if printf '%s\n' "$2" | grep -q -- "$3"; then fail "$1 ('$3' found)"; else pass "$1"; fi; }
sg_logtail() { tail -n 25 "$SG_LOG" | sed 's/^/         | /'; }

# sg_wait SECONDS DESCRIPTION CONDITION : poll the condition (evaluated by sh) every half second
sg_wait() {
    _w_n=$(( $1 * 2 )); _w_d=$2; shift 2; _w_i=0
    while [ "$_w_i" -lt "$_w_n" ]; do
        if eval "$*"; then pass "$_w_d"; return 0; fi
        sleep 0.5; _w_i=$((_w_i + 1))
    done
    fail "$_w_d (waited)"; sg_logtail
    return 1
}
sg_quiet_wait() {   # the same without a result line (the caller reports)
    _w_n=$(( $1 * 2 )); shift; _w_i=0
    while [ "$_w_i" -lt "$_w_n" ]; do
        if eval "$*"; then return 0; fi
        sleep 0.5; _w_i=$((_w_i + 1))
    done
    return 1
}

sg_alive() { _s=$(ps -o stat= -p "$1" 2>/dev/null | tr -d ' '); [ -n "$_s" ] && case $_s in Z*) return 1 ;; esac && [ -n "$_s" ]; }

# --- tools ---------------------------------------------------------------------------------------------------------------------------------
# a directory of BIND's tools where dnssec-signzone waits while the file $T/out/slow exists (so that a test can change a zone, or stop the signer, while
# the signer is signing); the other tools are links
sg_make_bt() {
    _real=$(dirname "$(command -v dnssec-signzone)")
    mkdir -p "$SG_BT"
    for t in dnssec-keygen dnssec-verify; do ln -sf "$_real/$t" "$SG_BT/$t"; done
    cat > "$SG_BT/dnssec-signzone" <<EOF
#!/bin/sh
z=""; p=""
for a in "\$@"; do [ "\$p" = -o ] && z=\$a; p=\$a; done
if [ -e "$T/out/slow" ] && [ "\$(cat "$T/out/slow.zone")" = "\$z" ]; then : > "$T/out/signing.\$z"; sleep \$(cat "$T/out/slow"); fi
exec "$_real/dnssec-signzone" "\$@"
EOF
    chmod 755 "$SG_BT/dnssec-signzone"
    chmod 755 "$SG_BT"
}
# sg_slow SECONDS ZONE: dnssec-signzone waits that long when it signs ZONE (the other zones are signed at the usual speed); $T/out/signing.ZONE says that it waits
sg_slow() { rm -f "$T/out/signing.$2"; echo "$2" > "$T/out/slow.zone"; echo "$1" > "$T/out/slow"; }
sg_unslow() { rm -f "$T/out/slow" "$T/out/slow.zone" "$T"/out/signing.*; }

# sg_write_conf [EXTRA-GLOBAL-LINES]: $SG_CONF; the database lines come from SG_DBCONF and the [zone ...] sections from SG_ZONES (set by the script)
sg_write_conf() {
    cat > "$SG_CONF" <<EOF
# karidns-signer test configuration
$SG_DBCONF
work-dir = $T/work
workers = ${SG_WORKERS:-2}
karidns-zone = ${SG_ZONE_BIN:-$ROOT/karidns-zone}
karicheck = ${SG_KARICHECK:-$ROOT/karicheck}
karictl = ${SG_KARICTL:-$ROOT/karictl}
bind-tools = $SG_BT
validity = 1h
refresh = 20m
jitter = 2m
debounce = 2
timeout = 120
log = stderr
${1:-}
${SG_ZONES:-}
EOF
    chmod 644 "$SG_CONF"
}

# --- the signer process --------------------------------------------------------------------------------------------------------------------
sg_start() {
    rm -f "$SG_PIDFILE"
    asu sh -c 'echo $$ > "$1"; shift; exec "$@"' sh "$SG_PIDFILE" "$NODE" "${SG_APP:-$ROOT/signer}/bin/karidns-signer.js" -c "$SG_CONF" >> "$SG_LOG" 2>&1 &
    SG_SHELL=$!
    sg_quiet_wait 10 '[ -s "$SG_PIDFILE" ]'
    SG_PID=$(cat "$SG_PIDFILE" 2>/dev/null)
    if sg_quiet_wait 20 'grep -q "karidns-signer 0.6.0 started" "$SG_LOG"'; then pass "the signer started (pid $SG_PID)"; else fail "the signer did not start"; sg_logtail; fi
}
# stop with SIGTERM and wait for the exit (a signer that is signing finishes the zone first)
sg_stop() {
    [ -n "$SG_PID" ] || return 0
    kill -TERM "$SG_PID" 2>/dev/null
    _i=0; while [ "$_i" -lt "${1:-60}" ] && sg_alive "$SG_PID"; do sleep 0.5; _i=$((_i + 1)); done
    if sg_alive "$SG_PID"; then fail "the signer did not stop after SIGTERM"; sg_kill_tree "$SG_PID"; fi
    wait "$SG_SHELL" 2>/dev/null
    SG_RC=$?
    SG_PID=""
}
# SIGKILL to a process and its descendants (children first).  Not kari_kill_tree: that stops each process first, and su(1), the parent of the signer when the
# test runs as root, stops itself when its child is stopped and never wakes up again.
sg_kill_tree() {
    for _c in $(pgrep -P "$1" 2>/dev/null); do sg_kill_tree "$_c"; done
    kill -KILL "$1" 2>/dev/null
}
sg_hard_kill() { sg_kill_tree "$SG_PID"; wait "$SG_SHELL" 2>/dev/null; SG_PID=""; }

sg_workdir_empty() { [ -z "$(ls -A "$T/work" 2>/dev/null)" ]; }

# --- zones ---------------------------------------------------------------------------------------------------------------------------------
mkdir -p "$T/z" "$T/out"
# sg_zone NAME SERIAL: the zone file; a delegation, an empty non-terminal, a CNAME and an MX are in it
sg_zone() {
    cat > "$T/z/$1.zone" <<EOF
\$ORIGIN $1.
\$TTL 300
@ IN SOA ns1 hostmaster $2 7200 3600 1209600 300
@ IN NS ns1
ns1 IN A 192.0.2.1
www IN A 192.0.2.2
alias IN CNAME www
mail IN MX 10 www
txt IN TXT "hello"
a.b.c IN A 192.0.2.3
sub IN NS ns.sub.example.net.
EOF
    chmod 644 "$T/z/$1.zone"
}
sg_import() {   # sg_import ZONE FILE [OPTIONS]: as the owner
    _z=$1; _f=$2; shift 2
    $ZI import "$@" $ZDB "$_z" "$_f" > "$T/imp.out" 2>&1 || { fail "import of $_z" "$(cat "$T/imp.out")"; return 1; }
}
sg_newzone() { sg_zone "$1" 1; sg_import "$1" "$T/z/$1.zone"; }
sg_export() {   # sg_export ZONE: $T/out/ZONE.zone
    rm -f "$T/out/$1.zone"
    $ZI export $ZDB "$1" "$T/out/$1.zone" > "$T/exp.out" 2>&1 || { fail "export of $1" "$(cat "$T/exp.out")"; return 1; }
}
# the same, quiet, for a condition that is polled: a zone that was changed and is not signed yet cannot be exported (the reader refuses a chain that is out of date)
sg_try_export() { rm -f "$T/out/$1.zone"; $ZI export $ZDB "$1" "$T/out/$1.zone" > /dev/null 2>&1; }
sg_domain_id() { dbq "SELECT id FROM domains WHERE name = '$1'"; }

# sg_request ZONE KIND ALG KEYTYPE [NSEC] [BITS]: file a key request as an operator would
sg_request() {
    _ns="NULL"; [ -n "${5:-}" ] && _ns="'$5'"
    _bits="NULL"; [ -n "${6:-}" ] && _bits="$6"
    dbq "INSERT INTO karidns_key_requests (domain_id, kind, algorithm, bits, key_type, nsec) SELECT id, '$2', $3, $_bits, '$4', $_ns FROM domains WHERE name = '$1'" > /dev/null
}
sg_req_state() { dbq "SELECT state FROM karidns_key_requests WHERE domain_id = (SELECT id FROM domains WHERE name = '$1') ORDER BY id DESC LIMIT 1"; }
sg_req_msg() { dbq "SELECT message FROM karidns_key_requests WHERE domain_id = (SELECT id FROM domains WHERE name = '$1') ORDER BY id DESC LIMIT 1"; }
sg_serial() { dbq "SELECT content FROM records WHERE type = 'SOA' AND name = '$1'" | awk '{ print $3 }'; }
sg_meta() { dbq "SELECT kind || '=' || content FROM domainmetadata WHERE domain_id = (SELECT id FROM domains WHERE name = '$1') ORDER BY kind" | tr '\012' ',' | sed 's/,$//'; }
sg_keys() { dbq "SELECT count(*) || ' ' || coalesce(sum(CASE WHEN flags = 257 THEN 1 ELSE 0 END), 0) || ' ' || coalesce(sum(CASE WHEN active THEN 1 ELSE 0 END), 0) FROM cryptokeys WHERE domain_id = (SELECT id FROM domains WHERE name = '$1')"; }
sg_state() { dbq "SELECT $2 FROM karidns_signer_state WHERE domain_id = (SELECT id FROM domains WHERE name = '$1')"; }
sg_signed_at() { sg_state "$1" "$SG_SIGNED_AT"; }
sg_due_now() { dbq "UPDATE karidns_signer_state SET next_due = $SG_DUE0 WHERE domain_id = (SELECT id FROM domains WHERE name = '$1')" > /dev/null; }
# sg_sig FILE OWNER TYPE exp|tag: the expiration (YYYYMMDDHHMMSS) or the key tag of the RRSIG(s) over OWNER's TYPE RRset in an exported zone; the
# fields after the word RRSIG are: type algorithm labels original-ttl expiration inception key-tag signer signature
sg_sig() {
    awk -v o="$2" -v t="$3" -v f="$4" '$1 == o { for (i = 2; i < NF; i++) if ($i == "RRSIG" && $(i + 1) == t) { print (f == "exp" ? $(i + 5) : $(i + 7)); next } }' "$1"
}
sg_ndnskey() { grep -cE '^@ ([0-9]+ )?DNSKEY ' "$T/out/$1.zone"; }
# every RRSIG row of the zone, as the database holds it (a checksum: the export refuses a zone that was changed and not signed yet)
sg_sigs() { dbq "SELECT name || ' ' || content FROM records WHERE type = 'RRSIG' AND domain_id = (SELECT id FROM domains WHERE name = '$1') ORDER BY name, content" | cksum; }

# sg_verify ZONE: export the zone as the server serves it and check it with BIND's dnssec-verify and with karicheck
sg_verify() {
    sg_export "$1" || return 1
    _vz=-z; [ "${2:-}" = split ] && _vz=""        # a CSK (a key with the KSK flag that signs everything) needs -z; a KSK + ZSK zone is checked strictly
    if "$SG_BT/dnssec-verify" $_vz -o "$1" "$T/out/$1.zone" > "$T/verify.out" 2>&1; then pass "$1: dnssec-verify accepts the zone as the database exports it"; else fail "$1: dnssec-verify" "$(cat "$T/verify.out")"; fi
    if "$ROOT/karicheck" zone "$1" "$T/out/$1.zone" > "$T/kc.out" 2>&1; then pass "$1: karicheck accepts it"; else fail "$1: karicheck" "$(cat "$T/kc.out")"; fi
}

# --- phase A: first signing by request, for every algorithm ---------------------------------------------------------------------------------
# alg13 (CSK, NSEC3), alg8 (RSA 2048, NSEC), alg10 (RSA 1024), alg14, alg15, alg16
sg_phase_algorithms() {
    echo "== A: first signing by request: algorithms 13 (ex.test), 8 (NSEC), 10, 14, 15, 16"
    for z in ex.test alg8.test alg10.test alg14.test alg15.test alg16.test; do sg_newzone "$z"; done
    sg_request ex.test enable 13 csk nsec3
    sg_request alg8.test enable 8 csk nsec 2048
    sg_request alg10.test enable 10 csk nsec3 1024
    sg_request alg14.test enable 14 csk nsec3
    sg_request alg15.test enable 15 csk nsec3
    sg_request alg16.test enable 16 csk nsec3
    sg_start
    for z in ex.test alg8.test alg10.test alg14.test alg15.test alg16.test; do
        sg_wait 120 "$z: the request is answered" '[ "$(sg_req_state '"$z"')" != pending ]'
        sg_eq "$z: the request is done" "$(sg_req_state "$z")" done
    done
    sg_has "ex.test: the request says which key" "$(sg_req_msg ex.test)" 'signing enabled: key [0-9]* (algorithm 13, flags 257)'
    sg_eq "ex.test: metadata PRESIGNED, NSEC3PARAM (no salt, 0 iterations, RFC 9276), X-KARIDNS-SIGNER" "$(sg_meta ex.test)" "NSEC3PARAM=1 0 0 -,PRESIGNED=1,X-KARIDNS-SIGNER=1"
    sg_eq "alg8.test: NSEC, so no NSEC3PARAM" "$(sg_meta alg8.test)" "PRESIGNED=1,X-KARIDNS-SIGNER=1"
    sg_eq "ex.test: one CSK (flags 257), active, stored after the signing" "$(sg_keys ex.test)" "1 1 1"
    sg_eq "ex.test: the key is the private key file without timing metadata" "$(dbq "SELECT count(*) FROM cryptokeys WHERE domain_id = (SELECT id FROM domains WHERE name = 'ex.test') AND content LIKE 'Private-key-format: v1.%' AND content NOT LIKE '%Created:%' AND content NOT LIKE '%Activate:%'")" 1
    sg_eq "ex.test: the SOA serial was incremented once" "$(sg_serial ex.test)" 2
    sg_eq "ex.test: state: attempts 0, no error" "$(sg_state ex.test "attempts || '|' || coalesce(last_error, '-')")" "0|-"
    sg_has "ex.test: state: signed_serial is the serial" "$(sg_state ex.test signed_serial)" '^2$'
    for z in ex.test alg8.test alg10.test alg14.test alg15.test alg16.test; do sg_verify "$z"; done
    sg_has "alg8.test: NSEC records (RSASHA256 key made by dnssec-keygen, public key computed by the signer)" "$(grep -c ' NSEC ' "$T/out/alg8.test.zone")" '^[1-9]'
    sg_has "ex.test: NSEC3 records" "$(grep -c ' NSEC3 ' "$T/out/ex.test.zone")" '^[1-9]'
    for a in 8 10 14 15 16; do
        sg_has "alg$a.test: the DNSKEY has algorithm $a" "$(grep -E 'DNSKEY 257 3 ' "$T/out/alg$a.test.zone" | head -1)" "DNSKEY 257 3 $a "
    done
    sg_has "ex.test: the DNSKEY has algorithm 13" "$(grep -E 'DNSKEY 257 3 ' "$T/out/ex.test.zone" | head -1)" "DNSKEY 257 3 13 "
    if sg_workdir_empty; then pass "the work directory is empty after the zones"; else fail "work directory not empty: $(ls -A "$T/work")"; fi
}

# --- phase B: no loop (our own writes are not changes), a record added with `import --mode merge` is signed ---------------------------------
sg_phase_own_writes() {
    echo "== B: our own writes are not changes; a change without a serial bump is signed"
    s0=$(sg_state ex.test signed_serial); n0=$(grep -c "signed ex.test" "$SG_LOG")
    sleep 9
    sg_eq "ex.test: not signed again by itself (the key INSERT and the import --signer rows are known as ours)" "$(sg_state ex.test signed_serial)" "$s0"
    sg_eq "...the log has one 'signed ex.test' line" "$(grep -c "signed ex.test" "$SG_LOG")" "$n0"
    sg_export ex.test; cp "$T/out/ex.test.zone" "$T/out/ex.before"
    printf '$ORIGIN ex.test.\n$TTL 300\nnew IN A 192.0.2.77\n' > "$T/z/new.part"; chmod 644 "$T/z/new.part"
    sg_import ex.test "$T/z/new.part" --mode merge
    sg_wait 60 "ex.test: the merge (no SOA, so no serial bump) is signed" '[ "$(sg_state ex.test signed_serial)" != "'"$s0"'" ]'
    sg_verify ex.test
    sg_has "ex.test: new.ex.test A has a signature" "$(grep -c '^new RRSIG A ' "$T/out/ex.test.zone")" '^1$'
    sg_eq "ex.test: the serial grew" "$([ "$(sg_serial ex.test)" -gt "$s0" ] && echo yes)" yes
    # dnssec-signzone -i keeps the signatures that are still good: the RRSIG of www A is the one it was
    sg_eq "ex.test: the signature of an unchanged RRset (www A) is kept" "$(grep '^www RRSIG A ' "$T/out/ex.test.zone")" "$(grep '^www RRSIG A ' "$T/out/ex.before")"
    sg_eq "ex.test: ...and the SOA signature is new" "$([ "$(grep '^@ RRSIG SOA ' "$T/out/ex.test.zone")" != "$(grep '^@ RRSIG SOA ' "$T/out/ex.before")" ] && echo new)" new
}

# --- phase C: a change during signing: exit status 3, signed again at once -------------------------------------------------------------------
sg_phase_changed() {
    echo "== C: a change while the zone is being signed (karidns-zone import --signer exit status 3)"
    n0=$(grep -c "changed while it was signed" "$SG_LOG")
    sg_slow 6 ex.test
    printf '$ORIGIN ex.test.\n$TTL 300\nfirst IN A 192.0.2.81\n' > "$T/z/first.part"; chmod 644 "$T/z/first.part"
    sg_import ex.test "$T/z/first.part" --mode merge
    sg_quiet_wait 30 '[ -e "$T/out/signing.ex.test" ]'
    if [ -e "$T/out/signing.ex.test" ]; then pass "ex.test: dnssec-signzone is running (waiting)"; else fail "the signer did not start signing"; sg_logtail; fi
    printf '$ORIGIN ex.test.\n$TTL 300\nsecond IN A 192.0.2.82\n' > "$T/z/second.part"; chmod 644 "$T/z/second.part"
    sg_import ex.test "$T/z/second.part" --mode merge
    sg_unslow
    sg_wait 90 "ex.test: the zone is signed again at once" '[ "$(grep -c "changed while it was signed" "$SG_LOG")" -gt '"$n0"' ]'
    sg_wait 60 "ex.test: both new records are signed in the end" 'sg_try_export ex.test; [ "$(grep -c "^first RRSIG A \|^second RRSIG A " "$T/out/ex.test.zone")" = 2 ]'
    sg_verify ex.test
    sg_eq "ex.test: no failure was recorded for it" "$(sg_state ex.test "attempts || '|' || coalesce(last_error, '-')")" "0|-"
}

# --- phase D: a change is served only after it is signed (S-5; root, with a server) ---------------------------------------------------------
sg_phase_served() {
    echo "== D: a change is served only when it is signed (signer-wait, S-5)"
    if [ "${SG_SERVER:-0}" != 1 ]; then echo "  SKIP: no server (needs root)"; return 0; fi
    sg_wait 30 "ex.test is served with its signatures" 'qa_dnssec www.ex.test A | grep -q RRSIG'
    sg_has "ex.test: DNSKEY served with an RRSIG" "$(qa_dnssec ex.test DNSKEY)" 'RRSIG'
    sg_has "ex.test: a name that does not exist gets NSEC3 records" "$(qa_dnssec nope.ex.test A)" 'NSEC3'
    # every zone the signer has signed so far has been reloaded after the loader read its change rows or before it: either way none waits (a one-zone
    # reload covers the rows it has read, the poll of the loader must not list the zone again)
    sg_wait 120 "no zone is on the list of the zones that wait for the signer (all are signed)" '! sg_dbstatus | grep -q "waiting for the signer"'
    sg_stop
    # a change of somebody else that bumps the serial, made at once (the same second as the last signature): the scan at the start finds it by the serial
    ser=$(sg_serial ex.test)
    sg_zone ex.test $((ser + 10))
    printf 'held IN A 192.0.2.91\n' >> "$T/z/ex.test.zone"
    sg_import ex.test "$T/z/ex.test.zone"
    sleep 4
    sg_hasnt "ex.test: the new record is NOT served while the signer is stopped" "$(qa_dnssec held.ex.test A)" '192.0.2.91'
    sg_eq "karictl dbstatus: exactly one zone waits for the signer, ex.test" "$(sg_dbstatus | grep 'waiting for the signer' | sed 's/^ *//')" "waiting for the signer: 1 zone(s): ex.test"
    sg_start
    sg_wait 60 "ex.test: after the signature the record is served" 'qa_dnssec held.ex.test A | grep -q 192.0.2.91'
    sg_has "ex.test: ...with its RRSIG" "$(qa_dnssec held.ex.test A)" 'RRSIG'
    sg_wait 60 "karictl dbstatus: the list of the zones that wait for the signer is empty again (and stays so)" '! sg_dbstatus | grep -q "waiting for the signer"'
    sleep 4
    sg_eq "...also after the poll of the loader has read the rows of the signature" "$(sg_dbstatus | grep -c 'waiting for the signer')" 0
}

# --- phase E: re-sign before the signatures expire ---------------------------------------------------------------------------------------
sg_phase_resign() {
    echo "== E: re-signing before expiry (fast.test: validity 60 s, refresh 20 s, jitter 5 s)"
    sg_newzone fast.test
    sg_request fast.test enable 13 csk nsec3
    sg_wait 60 "fast.test: signed" '[ "$(sg_req_state fast.test)" = done ]'
    sg_wait 30 "fast.test: exported" 'sg_try_export fast.test; [ -n "$(sg_sig "$T/out/fast.test.zone" "@" SOA exp)" ]'
    e0=$(sg_sig "$T/out/fast.test.zone" '@' SOA exp | sort -n | tail -1)
    a0=$(sg_signed_at fast.test); s0=$(sg_serial fast.test)
    d0=$(sg_state fast.test "$(echo "$SG_SIGNED_AT" | sed 's/signed_at/next_due/')")
    sg_has "fast.test: next_due is before the earliest expiration (min_expire - refresh)" "$(dbq "SELECT CASE WHEN next_due < min_expire THEN 'before' ELSE 'after' END FROM karidns_signer_state WHERE domain_id = (SELECT id FROM domains WHERE name = 'fast.test')")" before
    sg_wait 75 "fast.test: the signer signed it again (signed_at moved)" '[ "$(sg_signed_at fast.test)" != "'"$a0"'" ]'
    # not before it was due: the rows of the zone's creation, made just before the key request, are covered by the first run (Daemon.tick reads
    # the change log before it starts a run), they do not make the zone due a second time
    a1=$(sg_signed_at fast.test)
    sg_eq "fast.test: signed again when it was due, not before (signed_at $a1, next_due $d0)" "$([ -n "$d0" ] && [ "$a1" -ge "$d0" ] && echo due)" due
    sg_wait 30 "fast.test: the SOA signature expires later now" 'sg_try_export fast.test; e1=$(sg_sig "$T/out/fast.test.zone" "@" SOA exp | sort -n | tail -1); [ -n "$e1" ] && [ "$e1" -gt "$e0" ]'
    sg_eq "fast.test: the serial grew" "$([ "$(sg_serial fast.test)" -gt "$s0" ] && echo grew)" grew
    sg_verify fast.test
    sg_eq "fast.test: no attempts, no error" "$(sg_state fast.test "attempts || '|' || coalesce(last_error, '-')")" "0|-"
    # fast.test would be signed every 30 s for the rest of the test, and the work directory is looked at: it is not the signer's zone any more
    # (its metadata goes; the signer finds that at the next run of the zone and drops its state)
    dbq "DELETE FROM domainmetadata WHERE kind = 'X-KARIDNS-SIGNER' AND domain_id = (SELECT id FROM domains WHERE name = 'fast.test')" > /dev/null
    sg_due_now fast.test
    sg_wait 30 "fast.test: the signer drops a zone that is not its own any more (no state row)" '[ -z "$(sg_state fast.test attempts)" ]'
}

# --- phase F: NSEC3 opt-out, KSK + ZSK, an additional key ------------------------------------------------------------------------------------
sg_phase_variants() {
    echo "== F: NSEC3 opt-out, KSK + ZSK, request add"
    sg_newzone opt.test; sg_newzone split.test
    sg_request opt.test enable 13 csk nsec3
    sg_request split.test enable 15 ksk nsec3
    sg_wait 60 "opt.test: signed" '[ "$(sg_req_state opt.test)" = done ]'
    sg_wait 60 "split.test: signed" '[ "$(sg_req_state split.test)" = done ]'
    sg_export opt.test
    sg_has "opt.test: the NSEC3 records have the opt-out flag" "$(grep -c ' NSEC3 1 1 0 - ' "$T/out/opt.test.zone")" '^[1-9]'
    sg_hasnt "opt.test: the delegation has no NSEC3 record of its own (it is in the opt-out span)" "$(grep -c ' NSEC3 1 0 0 - ' "$T/out/opt.test.zone")" '^[1-9]'
    sg_verify opt.test
    sg_eq "split.test: two keys, one KSK, both active" "$(sg_keys split.test)" "2 1 2"
    sg_verify split.test split
    sg_export split.test
    ktag=$(sg_sig "$T/out/split.test.zone" '@' DNSKEY tag)
    ztag=$(sg_sig "$T/out/split.test.zone" www A tag)
    sg_eq "split.test: the DNSKEY RRset is signed by one key (the KSK)" "$(printf '%s
' "$ktag" | wc -l | tr -d ' ')" 1
    sg_eq "split.test: ...and www A by one key, the other one (the ZSK)" "$([ -n "$ztag" ] && [ "$ztag" != "$ktag" ] && echo different)" different
    # a key request of kind add: a second ZSK, the zone is signed with it
    s0=$(sg_state split.test signed_serial)
    sg_request split.test add 15 zsk
    sg_wait 60 "split.test: the add request is done" '[ "$(sg_req_state split.test)" = done ]'
    sg_has "split.test: ...with the key it added" "$(sg_req_msg split.test)" 'key [0-9]* (algorithm 15, flags 256) added'
    sg_eq "split.test: three keys" "$(sg_keys split.test)" "3 1 3"
    sg_wait 60 "split.test: the zone is signed again with the new key (three DNSKEYs)" 'sg_try_export split.test; [ "$(sg_ndnskey split.test)" = 3 ]'
    sg_verify split.test split
    sg_eq "split.test: the DNSKEY RRset has three keys" "$(sg_ndnskey split.test)" 3
    # requests that cannot be done are answered failed, with a reason, and change nothing
    sg_newzone plain.test
    sg_request plain.test add 13 zsk
    sg_wait 30 "plain.test: an add request for a zone that is not signed" '[ "$(sg_req_state plain.test)" = failed ]'
    sg_has "...says to request enable first" "$(sg_req_msg plain.test)" 'request kind enable first'
    sg_eq "...and no key was made" "$(sg_keys plain.test)" "0 0 0"
    dbq "INSERT INTO cryptokeys (domain_id, flags, active, published, content) SELECT id, 257, $SG_TRUE, $SG_TRUE, 'x' FROM domains WHERE name = 'plain.test'" > /dev/null
    sg_request plain.test enable 13 csk nsec3
    sg_wait 30 "plain.test: enable for a zone that has keys but is not signed" '[ "$(sg_req_state plain.test)" = failed ]'
    sg_has "...says the server would not serve it" "$(sg_req_msg plain.test)" 'cryptokeys rows but no PRESIGNED'
    dbq "DELETE FROM cryptokeys WHERE domain_id = (SELECT id FROM domains WHERE name = 'plain.test')" > /dev/null
}

# --- phase G: a key made by PowerDNS, a published-only key -----------------------------------------------------------------------------------
# the fixture is the output of PowerDNS 5.1 (cryptokeys.content, Private-key-format: v1.2) for an ECDSAP256SHA256 key-signing key (flags 257)
sg_pdns_key() {   # sg_pdns_key ZONE: prints the INSERT statement, and writes the public key (base64) to $T/pdns.pub
    "$NODE" -e '
      const fx = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).powerdns.find((k) => k.algorithm === 13 && k.flags === 257);
      require("fs").writeFileSync(process.argv[4], fx.dnskey.trim().split(/\s+/).slice(6).join(""));
      require("fs").writeFileSync(process.argv[5], String(fx.tag));
      const q = String.fromCharCode(39);
      process.stdout.write("INSERT INTO cryptokeys (domain_id, flags, active, published, content) SELECT id, " + fx.flags + ", " + process.argv[3] + ", " + process.argv[3] + ", " + q + fx.content.split(q).join(q + q) + q + " FROM domains WHERE name = " + q + process.argv[2] + q);
    ' "$ROOT/signer/test/fixtures/keys.json" "$1" "$SG_TRUE" "$T/pdns.pub" "$T/pdns.tag"
}
sg_phase_powerdns_key() {
    echo "== G: a key made by PowerDNS (Private-key-format: v1.2 in cryptokeys), and a key that is published only"
    pk=$(sg_pdns_key ex.test)
    dbq "$pk" > /dev/null
    sg_eq "ex.test: the PowerDNS key is in cryptokeys, next to the signer's own" "$(sg_keys ex.test)" "2 2 2"
    s0=$(sg_state ex.test signed_serial)
    sg_due_now ex.test
    sg_wait 60 "ex.test: the signer follows the columns of cryptokeys: signed with both keys (two DNSKEYs, the SOA signed by two keys)" 'sg_try_export ex.test; [ "$(sg_ndnskey ex.test)" = 2 ] && [ "$(sg_sig "$T/out/ex.test.zone" "@" SOA tag | sort -u | wc -l | tr -d " ")" = 2 ]'
    sg_verify ex.test
    sg_eq "ex.test: two DNSKEYs" "$(sg_ndnskey ex.test)" 2
    sg_has "ex.test: the DNSKEY RRset has the PowerDNS key (the public key was computed from the private key text)" "$(grep -E '^@ ([0-9]+ )?DNSKEY ' "$T/out/ex.test.zone" | tr -d ' ')" "$(cat "$T/pdns.pub")"
    sg_eq "ex.test: the SOA is signed by both keys" "$(sg_sig "$T/out/ex.test.zone" '@' SOA tag | sort -u | wc -l | tr -d ' ')" 2
    # the first key becomes published only: it signs nothing new, its DNSKEY stays in the zone (appended to the input, not passed to dnssec-signzone)
    dbq "UPDATE cryptokeys SET active = $SG_FALSE WHERE id = (SELECT min(id) FROM cryptokeys WHERE domain_id = (SELECT id FROM domains WHERE name = 'ex.test'))" > /dev/null
    sg_eq "ex.test: one key active, two published" "$(sg_keys ex.test)" "2 2 1"
    s0=$(sg_state ex.test signed_serial)
    sg_due_now ex.test
    sg_wait 60 "ex.test: signed again with the published-only key left out (the new serial)" '[ "$(sg_state ex.test signed_serial)" != "'"$s0"'" ]'
    sg_verify ex.test
    # (a signature that the retired key made over an RRset that did not change stays until it expires; dnssec-signzone cannot tell it from a good one)
    sg_has "ex.test: the new SOA is signed by the key that is active (the PowerDNS key, tag $(cat "$T/pdns.tag"))" "$(sg_sig "$T/out/ex.test.zone" '@' SOA tag)" "^$(cat "$T/pdns.tag")\$"
    sg_eq "ex.test: both DNSKEYs are still in the zone" "$(sg_ndnskey ex.test)" 2
    sg_eq "ex.test: no failure" "$(sg_state ex.test "attempts || '|' || coalesce(last_error, '-')")" "0|-"
}

# --- phase H: a broken key: the zone keeps its last good data ---------------------------------------------------------------------------------
sg_phase_broken_key() {
    echo "== H: a broken key: failed, the old data stays, the work directory is empty, no key material in the log"
    sg_newzone broken.test
    sg_request broken.test enable 13 csk nsec3
    sg_wait 60 "broken.test: signed" '[ "$(sg_req_state broken.test)" = done ]'
    sig0=$(sg_sigs broken.test); ser0=$(sg_serial broken.test)
    kid=$(dbq "SELECT id FROM cryptokeys WHERE domain_id = (SELECT id FROM domains WHERE name = 'broken.test')")
    orig=$(dbq "SELECT content FROM cryptokeys WHERE id = $kid")
    dbq "UPDATE cryptokeys SET content = 'Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: SECRET-NOT-BASE64!' WHERE id = $kid" > /dev/null
    printf '$ORIGIN broken.test.\n$TTL 300\nx IN A 192.0.2.99\n' > "$T/z/x.part"; chmod 644 "$T/z/x.part"
    sg_import broken.test "$T/z/x.part" --mode merge
    sg_wait 60 "broken.test: the run failed (attempts >= 1)" '[ "$(sg_state broken.test attempts)" -ge 1 ] 2>/dev/null'
    sg_has "broken.test: last_error says why" "$(sg_state broken.test last_error)" 'not base64'
    sg_hasnt "no key material in the log" "$(cat "$SG_LOG")" 'SECRET-NOT-BASE64'
    sg_hasnt "no key material in the state" "$(sg_state broken.test last_error)" 'SECRET-NOT-BASE64'
    sg_eq "broken.test: the signed data is the old data (every RRSIG row is unchanged)" "$(sg_sigs broken.test)" "$sig0"
    sg_eq "broken.test: the SOA serial was not touched by the signer" "$(sg_serial broken.test)" "$ser0"
    if sg_workdir_empty; then pass "the work directory is empty after the failure"; else fail "work directory not empty: $(ls -A "$T/work")"; fi
    # the operator puts the key back and resets the schedule: the zone is signed, the failure is forgotten
    dbq "UPDATE cryptokeys SET content = '$orig' WHERE id = $kid" > /dev/null
    sg_due_now broken.test
    sg_wait 60 "broken.test: signed again, attempts back to 0" '[ "$(sg_state broken.test attempts)" = 0 ]'
    sg_eq "broken.test: last_error is empty again" "$(sg_state broken.test "coalesce(last_error, '-')")" "-"
    sg_verify broken.test
    sg_has "broken.test: the new record is signed now" "$(grep -c '^x RRSIG A ' "$T/out/broken.test.zone")" '^1$'
}

# --- phase I: SIGHUP, SIGTERM during signing, kill -9 and the left-overs --------------------------------------------------------------------
sg_phase_signals() {
    echo "== I: SIGHUP, SIGTERM while a zone is signed, kill -9 and the left-overs"
    sg_write_conf "# changed" ""
    kill -HUP "$SG_PID"
    sg_wait 10 "SIGHUP: the configuration is read again" 'grep -q "configuration read again" "$SG_LOG"'
    printf 'workers = many\n' > "$T/bad.conf"
    cp "$SG_CONF" "$T/good.conf"; cp "$T/bad.conf" "$SG_CONF"
    kill -HUP "$SG_PID"
    sg_wait 10 "SIGHUP: a configuration with a mistake is refused, the signer goes on" 'grep -q "the configuration was not read: .*workers" "$SG_LOG"'
    cp "$T/good.conf" "$SG_CONF"
    sg_eq "...and is still running" "$(sg_alive "$SG_PID" && echo yes)" yes
    # SIGTERM while a zone is being signed: the zone is finished first
    sg_slow 5 ex.test
    printf '$ORIGIN ex.test.\n$TTL 300\nterm IN A 192.0.2.101\n' > "$T/z/term.part"; chmod 644 "$T/z/term.part"
    sg_import ex.test "$T/z/term.part" --mode merge
    sg_quiet_wait 30 '[ -e "$T/out/signing.ex.test" ]'
    s0=$(sg_state ex.test signed_serial)
    kill -TERM "$SG_PID"
    sleep 1
    sg_eq "SIGTERM: the signer is still running while the zone is signed" "$(sg_alive "$SG_PID" && echo yes)" yes
    sg_stop 60
    sg_eq "SIGTERM: exit status 0" "$SG_RC" 0
    sg_unslow
    sg_eq "SIGTERM: the zone was finished (signed_serial moved)" "$([ "$(sg_state ex.test signed_serial)" != "$s0" ] && echo moved)" moved
    sg_has "...and the log says so, in this order" "$(grep -n 'stopping\|signed ex.test\|stopped' "$SG_LOG" | tail -3 | sed 's/^[0-9]*://' | tr '\n' '|')" 'stopping.*|.*signed ex.test.*|.*stopped'
    if sg_workdir_empty; then pass "the work directory is empty after SIGTERM"; else fail "work directory not empty: $(ls -A "$T/work")"; fi
    # kill -9 while a zone is signed: the key files stay behind (that is the nature of kill -9), the next start wipes them
    sg_start
    sg_slow 20 ex.test
    printf '$ORIGIN ex.test.\n$TTL 300\nkilled IN A 192.0.2.102\n' > "$T/z/killed.part"; chmod 644 "$T/z/killed.part"
    sg_import ex.test "$T/z/killed.part" --mode merge
    sg_quiet_wait 30 '[ -e "$T/out/signing.ex.test" ]'
    sg_has "kill -9: a zone is being signed, its directory holds the key files" "$(ls "$T/work")" '^ex.test\.'
    sg_hard_kill
    sg_unslow
    sleep 1
    sg_has "kill -9: the left-overs of the dead signer are there" "$(ls -A "$T/work")" 'ex.test'
    sg_start
    sg_has "the next start wipes them and says so" "$(cat "$SG_LOG")" 'wiped [0-9]* work directory'
    sg_wait 60 "ex.test: the interrupted zone is signed by the restarted signer" 'sg_try_export ex.test; [ "$(grep -c "^killed RRSIG A " "$T/out/ex.test.zone")" = 1 ]'
    sg_wait 20 "the work directory is empty again" 'sg_workdir_empty'
    sg_verify ex.test
}

# --- phase J: --check ------------------------------------------------------------------------------------------------------------------------
sg_phase_check() {
    echo "== J: karidns-signer --check"
    asu "$NODE" "${SG_APP:-$ROOT/signer}/bin/karidns-signer.js" --check -c "$SG_CONF" > "$T/check.out" 2>&1; rc=$?
    sg_eq "--check of the test configuration: exit status 0" "$rc" 0
    sg_has "...it names the tools and their versions" "$(cat "$T/check.out")" 'dnssec-signzone .*: dnssec-signzone 9\.'
    sg_has "...and says the configuration is fine" "$(cat "$T/check.out")" 'the configuration is fine'
    printf 'database = %s\nwork-dir = %s\nkaridns-zone = /nonexistent/karidns-zone\n' "${SG_DBKIND}" "$T/work" > "$T/bad2.conf"
    asu "$NODE" "${SG_APP:-$ROOT/signer}/bin/karidns-signer.js" --check -c "$T/bad2.conf" > "$T/check2.out" 2>&1; rc=$?
    sg_eq "--check of a configuration with problems: exit status 1" "$rc" 1
    asu "$NODE" "${SG_APP:-$ROOT/signer}/bin/karidns-signer.js" --check -c "$T/nonexistent.conf" > "$T/check3.out" 2>&1; rc=$?
    sg_eq "--check of a file that is not there: exit status 1" "$rc" 1
    sg_has "...with the reason" "$(cat "$T/check3.out")" 'cannot read'
}

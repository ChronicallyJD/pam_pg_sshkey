#!/usr/bin/env bash
# check.sh, the end-to-end assertions.  Runs INSIDE the e2e container as
# root after provision.sh.  Each check is one vertical slice.
#
# Env:  E2E_ONLY=<name>   run a single check
#
# SPDX-License-Identifier: MIT
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

restore_chal_dir() { chown postgres:postgres "$CHAL_DIR"; chmod 1733 "$CHAL_DIR"; }
trap restore_chal_dir EXIT

PSQL_TCP="psql -h 127.0.0.1 -U alice -d alice -tA"
PSQL_TCP_CAROL="psql -h 127.0.0.1 -U carol -d carol -tA"
CAROL_CERT=/home/carol/.ssh/id_ed25519-cert.pub

# ── 2.1 ──────────────────────────────────────────────────────────────────────
check_tcp_connect_as_alice() {
    local cur off; cur=$(journal_mark); off=$(pglog_mark)
    local out; out=$(as_alice "pg_sshkey_connect -h 127.0.0.1 -- -tAc 'select current_user'" 2>&1) || { echo "$out"; return 1; }
    [[ "$out" == "alice" ]] || { echo "got: $out"; return 1; }
    # it must have been OUR module that let her in, not another hba method
    expect_journal "$cur" "pam_pg_sshkey: user 'alice' authenticated with key" || return 1
    expect_no_pglog "$off" 'PAM authentication failed'
}
# ── 2.2 ──────────────────────────────────────────────────────────────────────
check_local_socket_connect_as_alice() {
    local cur; cur=$(journal_mark)
    local out; out=$(as_alice "pg_sshkey_connect -- -tAc 'select current_user'" 2>&1) || { echo "$out"; return 1; }
    [[ "$out" == "alice" ]] || { echo "got: $out"; return 1; }
    # Ubuntu's default `local all all peer` would also admit alice: prove PAM did it
    expect_journal "$cur" "pam_pg_sshkey: user 'alice' authenticated with key"
}
# ── 2.3 ──────────────────────────────────────────────────────────────────────
check_pg_sshkey_query() {
    local out; out=$(as_alice "pg_sshkey_query -h 127.0.0.1 -q 'select current_user'" 2>&1) || { echo "$out"; return 1; }
    grep -q alice <<<"$out" || { echo "got: $out"; return 1; }
}
# ── 2.4 ──────────────────────────────────────────────────────────────────────
check_python_module_connect() {
    local out; out=$(as_alice "PYTHONPATH=$SRC/src python3 -c \"
from pam_pg_sshkey import connect
c = connect(user='alice', dbname='alice', host='127.0.0.1')
cur = c.cursor(); cur.execute('select current_user'); print(cur.fetchone()[0])\"" 2>&1) || { echo "$out"; return 1; }
    [[ "$out" == "alice" ]] || { echo "got: $out"; return 1; }
}
# ── 2.5 ──────────────────────────────────────────────────────────────────────
check_wrong_key_rejected() {
    local cur off; cur=$(journal_mark); off=$(pglog_mark)
    if as_alice "pg_sshkey_connect -h 127.0.0.1 -i ~/.ssh/id_wrong -- -tAc 'select 1'" >/dev/null 2>&1; then
        echo "connected with an unregistered key"; return 1
    fi
    expect_journal "$cur" "pam_pg_sshkey: authentication failed for 'alice'" || return 1
    expect_pglog  "$off" 'PAM authentication failed for user "alice"'
}
# ── 2.6 + 2.7 ────────────────────────────────────────────────────────────────
check_replayed_token_rejected() {
    local cur; cur=$(journal_mark)
    local out; out=$(as_alice "
        chal=\$(pg_sshkey_challenge $CHAL_DIR) || exit 9
        tok=\$(pg_sshkey_sign \"\$chal\" ~/.ssh/id_ed25519) || exit 9
        echo \"chal=\$chal\"
        PGPASSWORD=\$tok $PSQL_TCP -c 'select 1' 2>&1 && echo first=ok || echo first=fail
        PGPASSWORD=\$tok $PSQL_TCP -c 'select 1' >/dev/null 2>&1 && echo second=ok || echo second=fail
    " 2>&1)
    grep -q '^first=ok'    <<<"$out" || { echo "first use did not succeed:"; echo "$out"; return 1; }
    grep -q '^second=fail' <<<"$out" || { echo "REPLAY SUCCEEDED:"; echo "$out"; return 1; }
    expect_journal "$cur" "challenge not found or expired for 'alice'" || return 1
    local chal; chal=$(sed -n 's/^chal=//p' <<<"$out")
    [[ -n "$chal" && ! -e "$CHAL_DIR/$chal" ]] || { echo "nonce $chal still present after successful auth"; return 1; }
}
check_nonce_deleted_after_auth() {
    local out; out=$(as_alice "
        chal=\$(pg_sshkey_challenge $CHAL_DIR) || exit 9
        tok=\$(pg_sshkey_sign \"\$chal\" ~/.ssh/id_ed25519) || exit 9
        PGPASSWORD=\$tok $PSQL_TCP -c 'select 1' >/dev/null 2>&1 || exit 8
        echo \"\$chal\"
    " 2>&1) || { echo "auth failed: $out"; return 1; }
    [[ ! -e "$CHAL_DIR/$out" ]] || { echo "nonce $out still present"; return 1; }
}
# ── 2.8 ──────────────────────────────────────────────────────────────────────
check_bob_without_keys_rejected() {
    local cur; cur=$(journal_mark)
    if as_bob "pg_sshkey_connect -h 127.0.0.1 -- -tAc 'select 1'" >/dev/null 2>&1; then
        echo "bob connected with no authorized_keys"; return 1
    fi
    expect_journal "$cur" "pam_pg_sshkey: no authorized_keys for 'bob'"
}
# ── 2.9 ──────────────────────────────────────────────────────────────────────
check_malformed_token_rejected() {
    local cur; cur=$(journal_mark)
    if as_alice "PGPASSWORD=garbage $PSQL_TCP -c 'select 1'" >/dev/null 2>&1; then
        echo "garbage password accepted"; return 1
    fi
    expect_journal "$cur" "pam_pg_sshkey: malformed token for 'alice'"
}
# ── 2.10 ─────────────────────────────────────────────────────────────────────
check_root_owned_chal_dir_fails_closed() {
    local cur rc=0; cur=$(journal_mark)
    chown root:root "$CHAL_DIR"; chmod 1733 "$CHAL_DIR"
    local out; out=$(as_alice "
        chal=\$(pg_sshkey_challenge $CHAL_DIR) || exit 9
        tok=\$(pg_sshkey_sign \"\$chal\" ~/.ssh/id_ed25519) || exit 9
        PGPASSWORD=\$tok $PSQL_TCP -c 'select 1' >/dev/null 2>&1 && echo first=ok || echo first=fail
        PGPASSWORD=\$tok $PSQL_TCP -c 'select 1' >/dev/null 2>&1 && echo second=ok || echo second=fail
        echo \"chal=\$chal\"
    " 2>&1)
    restore_chal_dir
    local chal; chal=$(sed -n 's/^chal=//p' <<<"$out"); rm -f "$CHAL_DIR/$chal"
    grep -q '^first=fail'  <<<"$out" || { echo "auth succeeded although the nonce could not be consumed:"; echo "$out"; rc=1; }
    grep -q '^second=fail' <<<"$out" || { echo "REPLAY SUCCEEDED:"; echo "$out"; rc=1; }
    expect_journal "$cur" "could not delete challenge" || rc=1
    return $rc
}
# ── 2.11 ─────────────────────────────────────────────────────────────────────
check_umask_077_client_still_authenticates() {
    local out
    out=$(as_alice "umask 077; pg_sshkey_connect -h 127.0.0.1 -- -tAc 'select current_user'" 2>&1) \
        || { echo "C tools: $out"; return 1; }
    [[ "$out" == "alice" ]] || { echo "C tools got: $out"; return 1; }
    out=$(as_alice "PYTHONPATH=$SRC/src python3 -c \"
import os; os.umask(0o077)
from pam_pg_sshkey import connect
c = connect(user='alice', dbname='alice', host='127.0.0.1')
cur = c.cursor(); cur.execute('select current_user'); print(cur.fetchone()[0])\"" 2>&1) \
        || { echo "python: $out"; return 1; }
    [[ "$out" == "alice" ]] || { echo "python got: $out"; return 1; }
}
# ── 2.12 ─────────────────────────────────────────────────────────────────────
check_rsa_key_connect() {
    pg_sshkey_addkey alice /home/alice/.ssh/id_ed25519.pub >/dev/null || { echo "addkey failed"; return 1; }
    pg_sshkey_addkey -a alice /home/alice/.ssh/id_rsa_pem.pub >/dev/null || { echo "addkey -a failed"; return 1; }
    local out; out=$(as_alice "pg_sshkey_connect -h 127.0.0.1 -i ~/.ssh/id_rsa_pem -- -tAc 'select current_user'" 2>&1) \
        || { echo "$out"; return 1; }
    [[ "$out" == "alice" ]] || { echo "got: $out"; return 1; }
}

# ── v1 still accepted: explicit legacy flow via the server nonce file ───────
check_v1_token_still_accepted() {
    local cur; cur=$(journal_mark)
    local out; out=$(as_alice "pg_sshkey_connect --v1 -h 127.0.0.1 -- -tAc 'select current_user'" 2>&1) || { echo "$out"; return 1; }
    [[ "$out" == "alice" ]] || { echo "got: $out"; return 1; }
    expect_journal "$cur" "pam_pg_sshkey: user 'alice' authenticated with key"
}
# ── v2: replay of a self-issued token is rejected ───────────────────────────
check_v2_replay_rejected() {
    local cur; cur=$(journal_mark)
    local out; out=$(as_alice "
        tok=\$(pg_sshkey_sign ~/.ssh/id_ed25519) || exit 9
        PGPASSWORD=\$tok $PSQL_TCP -c 'select 1' >/dev/null 2>&1 && echo first=ok || echo first=fail
        PGPASSWORD=\$tok $PSQL_TCP -c 'select 1' >/dev/null 2>&1 && echo second=ok || echo second=fail
        echo \"nonce=\$(cut -d: -f2 <<<\"\$tok\")\"
    " 2>&1)
    grep -q '^first=ok'    <<<"$out" || { echo "first use did not succeed:"; echo "$out"; return 1; }
    grep -q '^second=fail' <<<"$out" || { echo "REPLAY SUCCEEDED:"; echo "$out"; return 1; }
    expect_journal "$cur" "replayed token for 'alice'" || return 1
    local nonce; nonce=$(sed -n 's/^nonce=//p' <<<"$out")
    [[ -f "$CHAL_DIR/$nonce" ]] || { echo "nonce marker $nonce not recorded"; return 1; }
    local owner; owner=$(stat -c %U:%a "$CHAL_DIR/$nonce")
    [[ "$owner" == "postgres:600" ]] || { echo "marker is $owner, expected postgres:600"; return 1; }
}
# ── v2: works with a private 0700 directory (no world-writable dir needed) ──
check_v2_private_0700_dir() {
    chmod 0700 "$CHAL_DIR"
    local rc=0 out
    # v1 clients cannot even create their nonce any more ...
    if as_alice "pg_sshkey_challenge $CHAL_DIR" >/dev/null 2>&1; then echo "v1 nonce creation succeeded in a 0700 dir?!"; rc=1; fi
    # ... but v2 logs in, and replays are still caught
    out=$(as_alice "pg_sshkey_connect -h 127.0.0.1 -- -tAc 'select current_user'" 2>&1) || { echo "v2 connect: $out"; rc=1; }
    [[ "$out" == "alice" ]] || { echo "v2 got: $out"; rc=1; }
    out=$(as_alice "PYTHONPATH=$SRC/src python3 -c \"
from pam_pg_sshkey import connect
c = connect(user='alice', dbname='alice', host='127.0.0.1')
cur = c.cursor(); cur.execute('select current_user'); print(cur.fetchone()[0])\"" 2>&1) || { echo "python: $out"; rc=1; }
    [[ "$out" == "alice" ]] || { echo "python got: $out"; rc=1; }
    restore_chal_dir
    return $rc
}
# ── v2: expired / future tokens rejected by the server clock ────────────────
check_v2_timestamp_window() {
    local cur; cur=$(journal_mark)
    local out; out=$(as_alice "
        old=\$(pg_sshkey_sign --at \$(( \$(date +%s) - 120 )) ~/.ssh/id_ed25519)
        fut=\$(pg_sshkey_sign --at \$(( \$(date +%s) + 300 )) ~/.ssh/id_ed25519)
        PGPASSWORD=\$old $PSQL_TCP -c 'select 1' >/dev/null 2>&1 && echo old=ok || echo old=fail
        PGPASSWORD=\$fut $PSQL_TCP -c 'select 1' >/dev/null 2>&1 && echo fut=ok || echo fut=fail
    " 2>&1)
    grep -q '^old=fail' <<<"$out" || { echo "EXPIRED TOKEN ACCEPTED: $out"; return 1; }
    grep -q '^fut=fail' <<<"$out" || { echo "FUTURE TOKEN ACCEPTED: $out"; return 1; }
    expect_journal "$cur" "expired or clock skew"
}
# ── v2: unwritable marker dir fails closed ─────────────────────────────────
check_v2_unrecordable_nonce_fails_closed() {
    local cur; cur=$(journal_mark)
    chown root:root "$CHAL_DIR"; chmod 0500 "$CHAL_DIR"
    local out; out=$(as_alice "pg_sshkey_connect -h 127.0.0.1 -- -tAc 'select 1'" 2>&1) && { restore_chal_dir; echo "AUTH SUCCEEDED with an unrecordable nonce"; return 1; }
    restore_chal_dir
    expect_journal "$cur" "could not record nonce"
}

# ── sweeper: stale nonces from anyone vanish on the next authentication ─────
check_stale_nonces_swept() {
    local stale1=$CHAL_DIR/4444444444444444444444444444444444444444444444444444444444444444
    local stale2=$CHAL_DIR/5555555555555555555555555555555555555555555555555555555555555555
    local live=$CHAL_DIR/6666666666666666666666666666666666666666666666666666666666666666
    for f in $stale1 $stale2; do printf '%s\n%s\n' "$(( $(date +%s) - 3600 ))" "$(basename $f)" > "$f"; chown bob "$f"; touch -d '1 hour ago' "$f"; done
    printf '%s\n%s\n' "$(date +%s)" "$(basename $live)" > "$live"; chown bob "$live"
    local out; out=$(as_alice "pg_sshkey_connect -h 127.0.0.1 -- -tAc 'select 1'" 2>&1) || { echo "$out"; rm -f $live; return 1; }
    local rc=0
    [[ ! -e $stale1 && ! -e $stale2 ]] || { echo "stale nonces survived an authentication"; rc=1; }
    [[ -e $live ]] || { echo "a live nonce belonging to another user was removed"; rc=1; }
    rm -f $stale1 $stale2 $live
    return $rc
}
# ── python replication connections (logical + physical) ─────────────────────
check_python_replication_connect() {
    local out; out=$(as_alice "PYTHONPATH=$SRC/src python3 -c \"
from pam_pg_sshkey import connect_replication
c = connect_replication(user='alice', dbname='alice', host='127.0.0.1')            # logical
cur = c.cursor(); cur.execute('IDENTIFY_SYSTEM'); print('logical', cur.fetchone()[0] != '')
c = connect_replication(user='alice', host='127.0.0.1', replication='yes')         # physical, libpq spelling
cur = c.cursor(); cur.execute('IDENTIFY_SYSTEM'); print('physical', cur.fetchone()[0] != '')\"" 2>&1) || { echo "$out"; return 1; }
    [[ "$out" == $'logical True\nphysical True' ]] || { echo "got: $out"; return 1; }
}
# ── pg_sshkey_query: bad SQL is a clean error ───────────────────────────────
check_pg_sshkey_query_bad_sql_clean_error() {
    local out; out=$(as_alice "pg_sshkey_query -h 127.0.0.1 -q 'SELEC 1'" 2>&1) && { echo "bad SQL exited 0"; return 1; }
    grep -q '^error: Query failed' <<<"$out" || { echo "no clean error line: $out"; return 1; }
    ! grep -q Traceback <<<"$out" || { echo "traceback leaked: $out"; return 1; }
}
# ── remote-client flow: nonce minted on the server over ssh ─────────────────
SSH_CHAL="ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o LogLevel=ERROR alice@127.0.0.1 pg_sshkey_challenge $CHAL_DIR"
check_ssh_challenge_cmd_connect() {
    local cur; cur=$(journal_mark)
    local out; out=$(as_alice "pg_sshkey_connect --v1 --challenge-cmd '$SSH_CHAL' -h 127.0.0.1 -- -tAc 'select current_user'" 2>&1) || { echo "shell: $out"; return 1; }
    [[ "$out" == "alice" ]] || { echo "shell got: $out"; return 1; }
    expect_journal "$cur" "pam_pg_sshkey: user 'alice' authenticated with key" || return 1
    out=$(as_alice "PYTHONPATH=$SRC/src python3 -c \"
from pam_pg_sshkey import connect
c = connect(user='alice', dbname='alice', host='127.0.0.1', challenge_cmd='$SSH_CHAL')
cur = c.cursor(); cur.execute('select current_user'); print(cur.fetchone()[0])\"" 2>&1) || { echo "python: $out"; return 1; }
    [[ "$out" == "alice" ]] || { echo "python got: $out"; return 1; }
}

# ── certificates (v3): carol has NO authorized_keys, only a CA-signed key ───
check_cert_connect_as_carol() {
    [[ ! -e /etc/pg_sshkeys/carol/authorized_keys ]] || { echo "carol has an authorized_keys file; the check would not prove the certificate path"; return 1; }
    local cur off; cur=$(journal_mark); off=$(pglog_mark)
    local out; out=$(as_carol "pg_sshkey_connect --cert $CAROL_CERT -h 127.0.0.1 -- -tAc 'select current_user'" 2>&1) || { echo "$out"; return 1; }
    [[ "$out" == "carol" ]] || { echo "got: $out"; return 1; }
    expect_journal "$cur" "pam_pg_sshkey: user 'carol' authenticated with certificate 'carol-key'" || return 1
    expect_no_pglog "$off" 'PAM authentication failed'
}
check_cert_python_connect() {
    local cur; cur=$(journal_mark)
    local out; out=$(as_carol "PYTHONPATH=$SRC/src python3 -c \"
from pam_pg_sshkey import connect
c = connect(user='carol', dbname='carol', host='127.0.0.1', cert_path='$CAROL_CERT')
cur = c.cursor(); cur.execute('select current_user'); print(cur.fetchone()[0])\"" 2>&1) || { echo "$out"; return 1; }
    [[ "$out" == "carol" ]] || { echo "got: $out"; return 1; }
    expect_journal "$cur" "pam_pg_sshkey: user 'carol' authenticated with certificate"
}
check_cert_pg_sshkey_query() {
    local cur; cur=$(journal_mark)
    local out; out=$(as_carol "pg_sshkey_query --cert $CAROL_CERT -h 127.0.0.1 -q 'select current_user'" 2>&1) || { echo "$out"; return 1; }
    grep -q carol <<<"$out" || { echo "got: $out"; return 1; }
    expect_journal "$cur" "pam_pg_sshkey: user 'carol' authenticated with certificate"
}
check_cert_untrusted_ca_rejected() {
    local cur; cur=$(journal_mark)
    if as_carol "pg_sshkey_connect --cert ~/.ssh/id_ed25519_untrusted-cert.pub -h 127.0.0.1 -- -tAc 'select 1'" >/dev/null 2>&1; then
        echo "connected with a certificate from an untrusted CA"; return 1
    fi
    expect_journal "$cur" "pam_pg_sshkey: certificate for 'carol' rejected: not signed by a trusted CA"
}
check_cert_expired_rejected() {
    local cur; cur=$(journal_mark)
    if as_carol "pg_sshkey_connect --cert ~/.ssh/id_ed25519_expired-cert.pub -h 127.0.0.1 -- -tAc 'select 1'" >/dev/null 2>&1; then
        echo "connected with an expired certificate"; return 1
    fi
    expect_journal "$cur" "pam_pg_sshkey: certificate for 'carol' rejected: expired"
}
check_cert_wrong_principal_rejected() {
    local cur; cur=$(journal_mark)
    if as_carol "pg_sshkey_connect --cert ~/.ssh/id_ed25519_bob-cert.pub -h 127.0.0.1 -- -tAc 'select 1'" >/dev/null 2>&1; then
        echo "connected with a certificate whose only principal is bob"; return 1
    fi
    expect_journal "$cur" "pam_pg_sshkey: certificate for 'carol' rejected: principal 'carol' not listed"
}
check_cert_replay_rejected() {
    local cur; cur=$(journal_mark)
    local out; out=$(as_carol "
        tok=\$(pg_sshkey_sign --cert $CAROL_CERT ~/.ssh/id_ed25519) || exit 9
        PGPASSWORD=\$tok $PSQL_TCP_CAROL -c 'select 1' >/dev/null 2>&1 && echo first=ok || echo first=fail
        PGPASSWORD=\$tok $PSQL_TCP_CAROL -c 'select 1' >/dev/null 2>&1 && echo second=ok || echo second=fail
        echo \"nonce=\$(cut -d: -f2 <<<\"\$tok\")\"
    " 2>&1)
    grep -q '^first=ok'    <<<"$out" || { echo "first use did not succeed:"; echo "$out"; return 1; }
    grep -q '^second=fail' <<<"$out" || { echo "REPLAY SUCCEEDED:"; echo "$out"; return 1; }
    expect_journal "$cur" "pam_pg_sshkey: replayed token for 'carol' (nonce already used)" || return 1
    local nonce; nonce=$(sed -n 's/^nonce=//p' <<<"$out")
    [[ -f "$CHAL_DIR/$nonce" ]] || { echo "nonce marker $nonce not recorded"; return 1; }
}
check_cert_alice_key_without_cert_still_works() {
    grep -q 'trusted_ca_keys=/etc/pg_sshkeys/trusted_ca_keys' /etc/pam.d/postgresql \
        || { echo "trusted_ca_keys is not set in /etc/pam.d/postgresql; the check would not prove coexistence"; return 1; }
    local cur; cur=$(journal_mark)
    local out; out=$(as_alice "pg_sshkey_connect -h 127.0.0.1 -- -tAc 'select current_user'" 2>&1) || { echo "v2: $out"; return 1; }
    [[ "$out" == "alice" ]] || { echo "v2 got: $out"; return 1; }
    expect_journal "$cur" "pam_pg_sshkey: user 'alice' authenticated with key" || return 1
    cur=$(journal_mark)
    out=$(as_alice "pg_sshkey_connect --v1 -h 127.0.0.1 -- -tAc 'select current_user'" 2>&1) || { echo "v1: $out"; return 1; }
    [[ "$out" == "alice" ]] || { echo "v1 got: $out"; return 1; }
    expect_journal "$cur" "pam_pg_sshkey: user 'alice' authenticated with key"
}

echo "=== pam_pg_sshkey e2e ($(. /etc/os-release; echo "$PRETTY_NAME"), $(runuser -u postgres -- psql -tAc 'show server_version')) ==="
run_check tcp_connect_as_alice
run_check local_socket_connect_as_alice
run_check pg_sshkey_query
run_check python_module_connect
run_check wrong_key_rejected
run_check replayed_token_rejected
run_check nonce_deleted_after_auth
run_check bob_without_keys_rejected
run_check malformed_token_rejected
run_check root_owned_chal_dir_fails_closed
run_check umask_077_client_still_authenticates
run_check rsa_key_connect
run_check v1_token_still_accepted
run_check v2_replay_rejected
run_check v2_private_0700_dir
run_check v2_timestamp_window
run_check v2_unrecordable_nonce_fails_closed
run_check stale_nonces_swept
run_check python_replication_connect
run_check pg_sshkey_query_bad_sql_clean_error
run_check ssh_challenge_cmd_connect
run_check cert_connect_as_carol
run_check cert_python_connect
run_check cert_pg_sshkey_query
run_check cert_untrusted_ca_rejected
run_check cert_expired_rejected
run_check cert_wrong_principal_rejected
run_check cert_replay_rejected
run_check cert_alice_key_without_cert_still_works
summary
